import logging
import ast

from llvmlite import ir
from pythonbpf.type_deducer import ctypes_to_ir
from pythonbpf.binary_ops import handle_binary_op

logger: logging.Logger = logging.getLogger(__name__)

XDP_ACTIONS = {
    "XDP_ABORTED": 0,
    "XDP_DROP": 1,
    "XDP_PASS": 2,
    "XDP_TX": 3,
    "XDP_REDIRECT": 4,
}


def _handle_none_return(builder) -> bool:
    """Handle return or return None -> returns 0."""
    builder.ret(ir.Constant(ir.IntType(64), 0))
    logger.debug("Generated default return: 0")
    return True


def _handle_typed_constant_return(call_type, return_value, builder, ret_type) -> bool:
    """Handle typed constant return like: return c_int64(42)"""

    # call_type = stmt.value.func.id
    expected_type = ctypes_to_ir(call_type)

    if expected_type != ret_type:
        raise ValueError(
            f"Return type mismatch: expected {ret_type}, got {expected_type}"
        )

    # return_value = stmt.value.args[0].value
    builder.ret(ir.Constant(ret_type, return_value))
    logger.debug(f"Generated typed constant return: {call_type}({return_value})")
    return True


def _handle_binop_return(arg, builder, ret_type, local_sym_tab) -> bool:
    """Handle return with binary operation: return c_int64(x + 1)"""

    # result = handle_binary_op(stmt.value.args[0], builder, None, local_sym_tab)
    result = handle_binary_op(arg, builder, None, local_sym_tab)

    if result is None:
        raise ValueError("Failed to evaluate binary operation in return statement")

    val, val_type = result

    if val_type != ret_type:
        raise ValueError(f"Return type mismatch: expected {ret_type}, got {val_type}")

    builder.ret(val)
    logger.debug(f"Generated binary operation return: {val}")
    return True


def _handle_variable_return(var_name, builder, ret_type, local_sym_tab) -> bool:
    """Handle return of a variable: return c_int64(my_var)"""

    # var_name = stmt.value.args[0].id

    if var_name not in local_sym_tab:
        raise ValueError(f"Undefined variable in return: {var_name}")

    var = local_sym_tab[var_name].var
    val = builder.load(var)

    if val.type != ret_type:
        raise ValueError(f"Return type mismatch: expected {ret_type}, got {val.type}")

    builder.ret(val)
    logger.debug(f"Generated variable return: {var_name}")
    return True


def _handle_xdp_return(stmt: ast.Return, builder, ret_type) -> bool:
    """Handle XDP returns"""
    if not isinstance(stmt.value, ast.Name):
        return False

    action_name = stmt.value.id

    if action_name not in XDP_ACTIONS:
        raise ValueError(
            f"Unknown XDP action: {action_name}. Available: {XDP_ACTIONS.keys()}"
        )

    value = XDP_ACTIONS[action_name]
    builder.ret(ir.Constant(ret_type, value))
    logger.debug(f"Generated XDP action return: {action_name} = {value}")
    return True
