import logging
from .dependency_handler import DependencyHandler

logger = logging.getLogger(__name__)


class IRGenerator:
    def __init__(self, module, handler: DependencyHandler):
        self.module = module
        self.handler: DependencyHandler = handler
        if not handler.is_ready:
            raise ImportError(
                "Semantic analysis of vmlinux imports failed. Cannot generate IR"
            )
