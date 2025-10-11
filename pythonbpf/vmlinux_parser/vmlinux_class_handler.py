import ast
import logging
from functools import lru_cache
import importlib
from .dependency_handler import DependencyHandler
from .dependency_node import DependencyNode
import ctypes

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    imported_module = importlib.import_module(module_name)
    return [name for name in dir(imported_module)], imported_module


# Recursive function that gets all the dependent classes and adds them to handler
def process_vmlinux_class(node, llvm_module, handler: DependencyHandler):
    symbols_in_module, imported_module = get_module_symbols("vmlinux")

    # Handle both node objects and type objects
    if hasattr(node, 'name'):
        current_symbol_name = node.name
    elif hasattr(node, '__name__'):
        current_symbol_name = node.__name__
    else:
        current_symbol_name = str(node)

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
    # If it's a ctypes-like structure with _fields_
    if hasattr(class_obj, '_fields_'):
        for field_name, field_type in class_obj._fields_:
            field_table[field_name] = field_type

    # If it's using __annotations__
    elif hasattr(class_obj, '__annotations__'):
        for field_name, field_type in class_obj.__annotations__.items():
            field_table[field_name] = field_type

    else:
        raise TypeError("Could not get required class and definition")

    logger.debug(f"Extracted fields for {current_symbol_name}: {field_table}")
    if handler.has_node(current_symbol_name):
        logger.info("Extraction pruned due to already available field")
        return True
    else:
        new_dep_node = DependencyNode(name=current_symbol_name)
        for elem_name, elem_type in field_table.items():
            module_name = getattr(elem_type, "__module__", None)
            if module_name == ctypes.__name__:
                new_dep_node.add_field(elem_name, elem_type, ready=True)
            elif module_name == "vmlinux":
                new_dep_node.add_field(elem_name, elem_type, ready=False)
                # Create a temporary node-like object for recursion
                temp_node = type('TempNode', (),
                                 {'name': elem_type.__name__ if hasattr(elem_type, '__name__') else str(elem_type)})()
                if process_vmlinux_class(temp_node, llvm_module, handler):
                    new_dep_node.set_field_ready(elem_name, True)
            else:
                raise ValueError(f"{elem_name} with type {elem_type} not supported in recursive resolver")
        handler.add_node(new_dep_node)

    return True
