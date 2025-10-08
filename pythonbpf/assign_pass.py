import ast
import logging
from llvmlite import ir
from pythonbpf.expr import eval_expr

logger = logging.getLogger(__name__)


def handle_variable_assignment(
    func, module, builder, var_name, rval, local_sym_tab, map_sym_tab, structs_sym_tab
):
    """Handle single named variable assignment."""

    if var_name not in local_sym_tab:
        logger.error(f"Variable {var_name} not declared.")
        return False

    var_ptr = local_sym_tab[var_name].var
    var_type = local_sym_tab[var_name].ir_type

    # NOTE: Special case for struct initialization
    if isinstance(rval, ast.Call) and isinstance(rval.func, ast.Name):
        struct_name = rval.func.id
        if struct_name in structs_sym_tab and len(rval.args) == 0:
            struct_info = structs_sym_tab[struct_name]
            ir_struct = struct_info.ir_type

            builder.store(ir.Constant(ir_struct, None), var_ptr)
            logger.info(f"Initialized struct {struct_name} for variable {var_name}")
            return True

    val_result = eval_expr(
        func, module, builder, rval, local_sym_tab, map_sym_tab, structs_sym_tab
    )
    if val_result is None:
        logger.error(f"Failed to evaluate value for {var_name}")
        return False

    val, val_type = val_result
    if val_type != var_type:
        if isinstance(val_type, ir.IntType) and isinstance(var_type, ir.IntType):
            # Allow implicit int widening
            if val_type.width < var_type.width:
                val = builder.sext(val, var_type)
                logger.info(f"Implicitly widened int for variable {var_name}")
            elif val_type.width > var_type.width:
                val = builder.trunc(val, var_type)
                logger.info(f"Implicitly truncated int for variable {var_name}")
        else:
            logger.error(
                f"Type mismatch for variable {var_name}: {val_type} vs {var_type}"
            )
            return False

    builder.store(val, var_ptr)
    logger.info(f"Assigned value to variable {var_name}")
    return True
