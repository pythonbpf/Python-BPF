import ast
import logging
from functools import lru_cache
import importlib
from .dependency_handler import DependencyHandler
from .dependency_node import DependencyNode

logger = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    imported_module = importlib.import_module(module_name)
    return [name for name in dir(imported_module)], imported_module

def process_vmlinux_class(node, llvm_module, handler: DependencyHandler, parent=""):
    symbols_in_module, imported_module = get_module_symbols("vmlinux")
    current_symbol_name = node.name
    if current_symbol_name not in symbols_in_module:
        raise ImportError(f"{current_symbol_name} not present in module vmlinux")
    logger.info(f"Resolving vmlinux class {current_symbol_name}")
    field_table = {}  # should contain the field and it's type.

    # Get the class object from the module
    class_obj = getattr(imported_module, current_symbol_name)

    # Below, I've written a general structure that gets class-info
    # everytime, no matter the format in which it is present

    # Inspect the class fields
    # Assuming class_obj has fields stored in some standard way
    #If it's a ctypes-like structure with _fields_
    if hasattr(class_obj, '_fields_'):
        for field_name, field_type in class_obj._fields_:
            field_table[field_name] = field_type

    # If it's using __annotations__
    elif hasattr(class_obj, '__annotations__'):
        for field_name, field_type in class_obj.__annotations__.items():
            field_table[field_name] = field_type

    else:
        raise TypeError("Could not get required class and definition")

    logger.info(f"Extracted fields for {current_symbol_name}: {field_table}")
    return field_table

