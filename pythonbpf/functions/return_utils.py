import logging
import ast

from llvmlite import ir

logger: logging.Logger = logging.getLogger(__name__)

XDP_ACTIONS = {
    "XDP_ABORTED": 0,
    "XDP_DROP": 1,
    "XDP_PASS": 2,
    "XDP_TX": 3,
    "XDP_REDIRECT": 4,
}


def handle_none_return(builder) -> bool:
    """Handle return or return None -> returns 0."""
    builder.ret(ir.Constant(ir.IntType(64), 0))
    logger.debug("Generated default return: 0")
    return True


def is_xdp_name(name: str) -> bool:
    """Check if a name is an XDP action"""
    return name in XDP_ACTIONS


def handle_xdp_return(stmt: ast.Return, builder, ret_type) -> bool:
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
