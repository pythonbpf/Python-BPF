import ast
import logging
from functools import lru_cache
import importlib

logger = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    module = importlib.import_module(module_name)
    return [name for name in dir(module)]

def process_vmlinux_class(node, module, num=0):
    symbols_in_module = get_module_symbols("vmlinux")

