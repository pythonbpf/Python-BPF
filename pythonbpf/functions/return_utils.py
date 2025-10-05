import logging
import ir

logger: logging.Logger = logging.getLogger(__name__)


def _handle_none_return(builder) -> bool:
    """Handle return or return None -> returns 0."""
    builder.ret(ir.Constant(ir.IntType(64), 0))
    logger.debug("Generated default return: 0")
    return True
