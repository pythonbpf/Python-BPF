import ast
import logging
from functools import lru_cache
import importlib
from .dependency_handler import DependencyHandler
from .dependency_node import DependencyNode

logger = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    module = importlib.import_module(module_name)
    return [name for name in dir(module)]

def process_vmlinux_class(node, module, handler: DependencyHandler, parent=""):
    symbols_in_module = get_module_symbols("vmlinux")
    current_symbol_name = node.name
    if current_symbol_name not in symbols_in_module:
        raise ImportError(f"{current_symbol_name} not present in module vmlinux")
    logger.info(f"Resolving vmlinux class {current_symbol_name}")
    # Now we find fields present in current class
    pass

