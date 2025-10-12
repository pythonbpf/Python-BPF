from llvmlite import ir
import ast
import logging
from typing import Any
from dataclasses import dataclass

from pythonbpf.helper import (
    HelperHandlerRegistry,
    reset_scratch_pool,
)
from pythonbpf.type_deducer import ctypes_to_ir
from pythonbpf.expr import eval_expr, handle_expr, convert_to_bool
from pythonbpf.assign_pass import (
    handle_variable_assignment,
    handle_struct_field_assignment,
)

from .return_utils import _handle_none_return, _handle_xdp_return, _is_xdp_name


logger = logging.getLogger(__name__)


@dataclass
class LocalSymbol:
    var: ir.AllocaInstr
    ir_type: ir.Type
    metadata: Any = None

    def __iter__(self):
        yield self.var
        yield self.ir_type
        yield self.metadata


def get_probe_string(func_node):
    """Extract the probe string from the decorator of the function node."""
    # TODO: right now we have the whole string in the section decorator
    # But later we can implement typed tuples for tracepoints and kprobes
    # For helper functions, we return "helper"

    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "bpfglobal":
            return None
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "section" and len(decorator.args) == 1:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    return "helper"


def handle_assign(
    func, module, builder, stmt, map_sym_tab, local_sym_tab, structs_sym_tab
):
    """Handle assignment statements in the function body."""

    # TODO: Support this later
    # GH #37
    if len(stmt.targets) != 1:
        logger.error("Multi-target assignment is not supported for now")
        return

    target = stmt.targets[0]
    rval = stmt.value

    if isinstance(target, ast.Name):
        # NOTE: Simple variable assignment case: x = 5
        var_name = target.id
        result = handle_variable_assignment(
            func,
            module,
            builder,
            var_name,
            rval,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
        if not result:
            logger.error(f"Failed to handle assignment to {var_name}")
        return

    if isinstance(target, ast.Attribute):
        # NOTE: Struct field assignment case: pkt.field = value
        handle_struct_field_assignment(
            func,
            module,
            builder,
            target,
            rval,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
        return

    # Unsupported target type
    logger.error(f"Unsupported assignment target: {ast.dump(target)}")


def handle_cond(
    func, module, builder, cond, local_sym_tab, map_sym_tab, structs_sym_tab=None
):
    val = eval_expr(
        func, module, builder, cond, local_sym_tab, map_sym_tab, structs_sym_tab
    )[0]
    return convert_to_bool(builder, val)


def handle_if(
    func, module, builder, stmt, map_sym_tab, local_sym_tab, structs_sym_tab=None
):
    """Handle if statements in the function body."""
    logger.info("Handling if statement")
    # start = builder.block.parent
    then_block = func.append_basic_block(name="if.then")
    merge_block = func.append_basic_block(name="if.end")
    if stmt.orelse:
        else_block = func.append_basic_block(name="if.else")
    else:
        else_block = None

    cond = handle_cond(
        func, module, builder, stmt.test, local_sym_tab, map_sym_tab, structs_sym_tab
    )
    if else_block:
        builder.cbranch(cond, then_block, else_block)
    else:
        builder.cbranch(cond, then_block, merge_block)

    builder.position_at_end(then_block)
    for s in stmt.body:
        process_stmt(
            func, module, builder, s, local_sym_tab, map_sym_tab, structs_sym_tab, False
        )
    if not builder.block.is_terminated:
        builder.branch(merge_block)

    if else_block:
        builder.position_at_end(else_block)
        for s in stmt.orelse:
            process_stmt(
                func,
                module,
                builder,
                s,
                local_sym_tab,
                map_sym_tab,
                structs_sym_tab,
                False,
            )
        if not builder.block.is_terminated:
            builder.branch(merge_block)

    builder.position_at_end(merge_block)


def handle_return(builder, stmt, local_sym_tab, ret_type):
    logger.info(f"Handling return statement: {ast.dump(stmt)}")
    if stmt.value is None:
        return _handle_none_return(builder)
    elif isinstance(stmt.value, ast.Name) and _is_xdp_name(stmt.value.id):
        return _handle_xdp_return(stmt, builder, ret_type)
    else:
        val = eval_expr(
            func=None,
            module=None,
            builder=builder,
            expr=stmt.value,
            local_sym_tab=local_sym_tab,
            map_sym_tab={},
            structs_sym_tab={},
        )
        logger.info(f"Evaluated return expression to {val}")
        builder.ret(val[0])
        return True


def process_stmt(
    func,
    module,
    builder,
    stmt,
    local_sym_tab,
    map_sym_tab,
    structs_sym_tab,
    did_return,
    ret_type=ir.IntType(64),
):
    logger.info(f"Processing statement: {ast.dump(stmt)}")
    reset_scratch_pool()
    if isinstance(stmt, ast.Expr):
        handle_expr(
            func,
            module,
            builder,
            stmt,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
        )
    elif isinstance(stmt, ast.Assign):
        handle_assign(
            func, module, builder, stmt, map_sym_tab, local_sym_tab, structs_sym_tab
        )
    elif isinstance(stmt, ast.AugAssign):
        raise SyntaxError("Augmented assignment not supported")
    elif isinstance(stmt, ast.If):
        handle_if(
            func, module, builder, stmt, map_sym_tab, local_sym_tab, structs_sym_tab
        )
    elif isinstance(stmt, ast.Return):
        did_return = handle_return(
            builder,
            stmt,
            local_sym_tab,
            ret_type,
        )
    return did_return


def count_temps_in_call(call_node, local_sym_tab):
    """Count the number of temporary variables needed for a function call."""

    count = 0
    is_helper = False

    # NOTE: We exclude print calls for now
    if isinstance(call_node.func, ast.Name):
        if (
            HelperHandlerRegistry.has_handler(call_node.func.id)
            and call_node.func.id != "print"
        ):
            is_helper = True
    elif isinstance(call_node.func, ast.Attribute):
        if HelperHandlerRegistry.has_handler(call_node.func.attr):
            is_helper = True

    if not is_helper:
        return 0

    for arg in call_node.args:
        # NOTE: Count all non-name arguments
        # For struct fields, if it is being passed as an argument,
        # The struct object should already exist in the local_sym_tab
        if not isinstance(arg, ast.Name) and not (
            isinstance(arg, ast.Attribute) and arg.value.id in local_sym_tab
        ):
            count += 1

    return count


def allocate_mem(
    module, builder, body, func, ret_type, map_sym_tab, local_sym_tab, structs_sym_tab
):
    double_alloc = False
    max_temps_needed = 0

    def update_max_temps_for_stmt(stmt):
        nonlocal max_temps_needed
        temps_needed = 0

        if isinstance(stmt, ast.If):
            for s in stmt.body:
                update_max_temps_for_stmt(s)
            for s in stmt.orelse:
                update_max_temps_for_stmt(s)
            return

        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                temps_needed += count_temps_in_call(node, local_sym_tab)
        max_temps_needed = max(max_temps_needed, temps_needed)

    for stmt in body:
        update_max_temps_for_stmt(stmt)
        has_metadata = False
        if isinstance(stmt, ast.If):
            if stmt.body:
                local_sym_tab = allocate_mem(
                    module,
                    builder,
                    stmt.body,
                    func,
                    ret_type,
                    map_sym_tab,
                    local_sym_tab,
                    structs_sym_tab,
                )
            if stmt.orelse:
                local_sym_tab = allocate_mem(
                    module,
                    builder,
                    stmt.orelse,
                    func,
                    ret_type,
                    map_sym_tab,
                    local_sym_tab,
                    structs_sym_tab,
                )
        elif isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1:
                logger.info("Unsupported multiassignment")
                continue
            target = stmt.targets[0]
            if not isinstance(target, ast.Name) and not isinstance(
                target, ast.Attribute
            ):
                logger.info("Unsupported assignment target")
                continue
            if isinstance(target, ast.Attribute):
                logger.info(
                    f"Struct field {target.attr} assignment, will be handled later"
                )
                continue
            var_name = target.id
            rval = stmt.value
            if var_name in local_sym_tab:
                logger.info(f"Variable {var_name} already allocated")
                continue
            if isinstance(rval, ast.Call):
                if isinstance(rval.func, ast.Name):
                    call_type = rval.func.id
                    if call_type in ("c_int32", "c_int64", "c_uint32", "c_uint64"):
                        ir_type = ctypes_to_ir(call_type)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        logger.info(
                            f"Pre-allocated variable {var_name} of type {call_type}"
                        )
                    elif HelperHandlerRegistry.has_handler(call_type):
                        # Assume return type is int64 for now
                        ir_type = ir.IntType(64)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        logger.info(f"Pre-allocated variable {var_name} for helper")
                    elif call_type == "deref" and len(rval.args) == 1:
                        # Assume return type is int64 for now
                        ir_type = ir.IntType(64)
                        var = builder.alloca(ir_type, name=var_name)
                        var.align = ir_type.width // 8
                        logger.info(f"Pre-allocated variable {var_name} for deref")
                    elif call_type in structs_sym_tab:
                        struct_info = structs_sym_tab[call_type]
                        ir_type = struct_info.ir_type
                        var = builder.alloca(ir_type, name=var_name)
                        has_metadata = True
                        logger.info(
                            f"Pre-allocated variable {var_name} for struct {call_type}"
                        )
                elif isinstance(rval.func, ast.Attribute):
                    # Map method call
                    ir_type = ir.PointerType(ir.IntType(64))
                    var = builder.alloca(ir_type, name=var_name)

                    # declare an intermediate ptr type for map lookup
                    tmp_ir_type = ir.IntType(64)
                    var_tmp = builder.alloca(tmp_ir_type, name=f"{var_name}_tmp")
                    double_alloc = True
                    # var.align = ir_type.width // 8
                    logger.info(
                        f"Pre-allocated variable {var_name} and {var_name}_tmp for map"
                    )
                else:
                    logger.info("Unsupported assignment call function type")
                    continue
            elif isinstance(rval, ast.Constant):
                if isinstance(rval.value, bool):
                    ir_type = ir.IntType(1)
                    var = builder.alloca(ir_type, name=var_name)
                    var.align = 1
                    logger.info(f"Pre-allocated variable {var_name} of type c_bool")
                elif isinstance(rval.value, int):
                    # Assume c_int64 for now
                    ir_type = ir.IntType(64)
                    var = builder.alloca(ir_type, name=var_name)
                    var.align = ir_type.width // 8
                    logger.info(f"Pre-allocated variable {var_name} of type c_int64")
                elif isinstance(rval.value, str):
                    ir_type = ir.PointerType(ir.IntType(8))
                    var = builder.alloca(ir_type, name=var_name)
                    var.align = 8
                    logger.info(f"Pre-allocated variable {var_name} of type string")
                else:
                    logger.info("Unsupported constant type")
                    continue
            elif isinstance(rval, ast.BinOp):
                # Assume c_int64 for now
                ir_type = ir.IntType(64)
                var = builder.alloca(ir_type, name=var_name)
                var.align = ir_type.width // 8
                logger.info(f"Pre-allocated variable {var_name} of type c_int64")
            else:
                logger.info("Unsupported assignment value type")
                continue

            if has_metadata:
                local_sym_tab[var_name] = LocalSymbol(var, ir_type, call_type)
            else:
                local_sym_tab[var_name] = LocalSymbol(var, ir_type)

            if double_alloc:
                local_sym_tab[f"{var_name}_tmp"] = LocalSymbol(var_tmp, tmp_ir_type)

    logger.info(f"Temporary scratch space needed for calls: {max_temps_needed}")
    for i in range(max_temps_needed):
        temp_var = builder.alloca(ir.IntType(64), name=f"__helper_temp_{i}")
        temp_var.align = 8
        local_sym_tab[f"__helper_temp_{i}"] = LocalSymbol(temp_var, ir.IntType(64))

    return local_sym_tab


def process_func_body(
    module, builder, func_node, func, ret_type, map_sym_tab, structs_sym_tab
):
    """Process the body of a bpf function"""
    # TODO: A lot.  We just have print -> bpf_trace_printk for now
    did_return = False

    local_sym_tab = {}

    # pre-allocate dynamic variables
    local_sym_tab = allocate_mem(
        module,
        builder,
        func_node.body,
        func,
        ret_type,
        map_sym_tab,
        local_sym_tab,
        structs_sym_tab,
    )

    logger.info(f"Local symbol table: {local_sym_tab.keys()}")

    for stmt in func_node.body:
        did_return = process_stmt(
            func,
            module,
            builder,
            stmt,
            local_sym_tab,
            map_sym_tab,
            structs_sym_tab,
            did_return,
            ret_type,
        )

    if not did_return:
        builder.ret(ir.Constant(ir.IntType(64), 0))


def process_bpf_chunk(func_node, module, return_type, map_sym_tab, structs_sym_tab):
    """Process a single BPF chunk (function) and emit corresponding LLVM IR."""

    func_name = func_node.name

    ret_type = return_type

    # TODO: parse parameters
    param_types = []
    if func_node.args.args:
        # Assume first arg to be ctx
        param_types.append(ir.PointerType())

    func_ty = ir.FunctionType(ret_type, param_types)
    func = ir.Function(module, func_ty, func_name)

    func.linkage = "dso_local"
    func.attributes.add("nounwind")
    func.attributes.add("noinline")
    func.attributes.add("optnone")

    if func_node.args.args:
        # Only look at the first argument for now
        param = func.args[0]
        param.add_attribute("nocapture")

    probe_string = get_probe_string(func_node)
    if probe_string is not None:
        func.section = probe_string

    block = func.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)

    process_func_body(
        module, builder, func_node, func, ret_type, map_sym_tab, structs_sym_tab
    )
    return func


def func_proc(tree, module, chunks, map_sym_tab, structs_sym_tab):
    for func_node in chunks:
        is_global = False
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id in (
                "map",
                "bpfglobal",
                "struct",
            ):
                is_global = True
                break
        if is_global:
            continue
        func_type = get_probe_string(func_node)
        logger.info(f"Found probe_string of {func_node.name}: {func_type}")

        process_bpf_chunk(
            func_node,
            module,
            ctypes_to_ir(infer_return_type(func_node)),
            map_sym_tab,
            structs_sym_tab,
        )


def infer_return_type(func_node: ast.FunctionDef):
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise TypeError("Expected ast.FunctionDef")
    if func_node.returns is not None:
        try:
            return ast.unparse(func_node.returns)
        except Exception:
            node = func_node.returns
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return getattr(node, "attr", type(node).__name__)
            try:
                return str(node)
            except Exception:
                return type(node).__name__
    found_type = None

    def _expr_type(e):
        if e is None:
            return "None"
        if isinstance(e, ast.Constant):
            return type(e.value).__name__
        if isinstance(e, ast.Name):
            return e.id
        if isinstance(e, ast.Call):
            f = e.func
            if isinstance(f, ast.Name):
                return f.id
            if isinstance(f, ast.Attribute):
                try:
                    return ast.unparse(f)
                except Exception:
                    return getattr(f, "attr", type(f).__name__)
            try:
                return ast.unparse(f)
            except Exception:
                return type(f).__name__
        if isinstance(e, ast.Attribute):
            try:
                return ast.unparse(e)
            except Exception:
                return getattr(e, "attr", type(e).__name__)
        try:
            return ast.unparse(e)
        except Exception:
            return type(e).__name__

    for walked_node in ast.walk(func_node):
        if isinstance(walked_node, ast.Return):
            t = _expr_type(walked_node.value)
            if found_type is None:
                found_type = t
            elif found_type != t:
                raise ValueError(f"Conflicting return types: {found_type} vs {t}")
    return found_type or "None"


# For string assignment to fixed-size arrays


def assign_string_to_array(builder, target_array_ptr, source_string_ptr, array_length):
    """
    Copy a string (i8*) to a fixed-size array ([N x i8]*)
    """
    # Create a loop to copy characters one by one
    # entry_block = builder.block
    copy_block = builder.append_basic_block("copy_char")
    end_block = builder.append_basic_block("copy_end")

    # Create loop counter
    i = builder.alloca(ir.IntType(32))
    builder.store(ir.Constant(ir.IntType(32), 0), i)

    # Start the loop
    builder.branch(copy_block)

    # Copy loop
    builder.position_at_end(copy_block)
    idx = builder.load(i)
    in_bounds = builder.icmp_unsigned(
        "<", idx, ir.Constant(ir.IntType(32), array_length)
    )
    builder.cbranch(in_bounds, copy_block, end_block)

    with builder.if_then(in_bounds):
        # Load character from source
        src_ptr = builder.gep(source_string_ptr, [idx])
        char = builder.load(src_ptr)

        # Store character in target
        dst_ptr = builder.gep(target_array_ptr, [ir.Constant(ir.IntType(32), 0), idx])
        builder.store(char, dst_ptr)

        # Increment counter
        next_idx = builder.add(idx, ir.Constant(ir.IntType(32), 1))
        builder.store(next_idx, i)

    builder.position_at_end(end_block)

    # Ensure null termination
    last_idx = ir.Constant(ir.IntType(32), array_length - 1)
    null_ptr = builder.gep(target_array_ptr, [ir.Constant(ir.IntType(32), 0), last_idx])
    builder.store(ir.Constant(ir.IntType(8), 0), null_ptr)
