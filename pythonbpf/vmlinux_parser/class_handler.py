import logging
from functools import lru_cache
import importlib
from .dependency_handler import DependencyHandler
from .dependency_node import DependencyNode
import ctypes
from typing import Optional, Any

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    imported_module = importlib.import_module(module_name)
    return [name for name in dir(imported_module)], imported_module


def process_vmlinux_class(node, llvm_module, handler: DependencyHandler):
    symbols_in_module, imported_module = get_module_symbols("vmlinux")
    if node.name in symbols_in_module:
        vmlinux_type = getattr(imported_module, node.name)
        process_vmlinux_post_ast(vmlinux_type, llvm_module, handler)
    else:
        raise ImportError(f"{node.name} not in vmlinux")


def process_vmlinux_post_ast(
    elem_type_class, llvm_handler, handler: DependencyHandler, processing_stack=None
):
    # Initialize processing stack on first call
    if processing_stack is None:
        processing_stack = set()
    symbols_in_module, imported_module = get_module_symbols("vmlinux")

    current_symbol_name = elem_type_class.__name__
    field_table = {}
    is_complex_type = False
    containing_type: Optional[Any] = None
    ctype_complex_type: Optional[Any] = None
    type_length: Optional[int] = None
    module_name = getattr(elem_type_class, "__module__", None)

    if hasattr(elem_type_class, "_length_") and is_complex_type:
        type_length = elem_type_class._length_

    if current_symbol_name in processing_stack:
        logger.debug(
            f"Circular dependency detected for {current_symbol_name}, skipping"
        )
        return True

    # Check if already processed
    if handler.has_node(current_symbol_name):
        existing_node = handler.get_node(current_symbol_name)
        # If the node exists and is ready, we're done
        if existing_node and existing_node.is_ready:
            logger.info(f"Node {current_symbol_name} already processed and ready")
            return True

    processing_stack.add(current_symbol_name)

    if module_name == "vmlinux":
        if hasattr(elem_type_class, "_type_"):
            is_complex_type = True
            containing_type = elem_type_class._type_
            if containing_type.__module__ == "vmlinux":
                print("Very weird type ig for containing type", containing_type)
            elif containing_type.__module__ == ctypes.__name__:
                if isinstance(elem_type_class, type):
                    if issubclass(elem_type_class, ctypes.Array):
                        ctype_complex_type = ctypes.Array
                    elif issubclass(elem_type_class, ctypes._Pointer):
                        ctype_complex_type = ctypes._Pointer
                else:
                    raise TypeError("Unsupported ctypes subclass")
                # handle ctype complex type

            else:
                raise ImportError(f"Unsupported module of {containing_type}")
        else:
            new_dep_node = DependencyNode(name=current_symbol_name)
            handler.add_node(new_dep_node)
            class_obj = getattr(imported_module, current_symbol_name)
            # Inspect the class fields
            if hasattr(class_obj, "_fields_"):
                for field_name, field_type in class_obj._fields_:
                    field_table[field_name] = field_type
            elif hasattr(class_obj, "__annotations__"):
                for field_name, field_type in class_obj.__annotations__.items():
                    field_table[field_name] = field_type
            else:
                raise TypeError("Could not get required class and definition")

            logger.info(f"Extracted fields for {current_symbol_name}: {field_table}")

            for elem_name, elem_type in field_table.items():
                local_module_name = getattr(elem_type, "__module__", None)
                if local_module_name == ctypes.__name__:
                    new_dep_node.add_field(elem_name, elem_type, ready=True)
                    logger.info(f"Field {elem_name} is direct ctypes type: {elem_type}")
                elif local_module_name == "vmlinux":
                    new_dep_node.add_field(elem_name, elem_type, ready=False)
                    logger.debug(
                        f"Processing vmlinux field: {elem_name}, type: {elem_type}"
                    )
                    if process_vmlinux_post_ast(
                        elem_type, llvm_handler, handler, processing_stack
                    ):
                        new_dep_node.set_field_ready(elem_name, True)
                else:
                    raise ValueError(
                        f"{elem_name} with type {elem_type} from module {module_name} not supported in recursive resolver"
                    )
            print("")

    else:
        raise ImportError("UNSUPPORTED Module")

    print(current_symbol_name, "DONE")
    print(f"handler readiness {handler.is_ready}")
