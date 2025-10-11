import ast
import logging
import importlib

logger = logging.getLogger(__name__)


def get_module_symbols(module_name: str):
    module = importlib.import_module(module_name)
    return [name for name in dir(module)]

def process_vmlinux_class(node, module):
    # Process ClassDef nodes that use vmlinux imports
    symbols = get_module_symbols("vmlinux")
    # print(symbols)
    pass