import logging
from functools import lru_cache
import importlib

from .dependency_handler import DependencyHandler
from .dependency_node import DependencyNode
import ctypes
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_module_symbols(module_name: str):
    imported_module = importlib.import_module(module_name)
    return [name for name in dir(imported_module)], imported_module


def process_vmlinux_class(
    node,
    llvm_module,
    handler: DependencyHandler,
):
    symbols_in_module, imported_module = get_module_symbols("vmlinux")
    if node.name in symbols_in_module:
        vmlinux_type = getattr(imported_module, node.name)
        process_vmlinux_post_ast(vmlinux_type, llvm_module, handler)
    else:
        raise ImportError(f"{node.name} not in vmlinux")


def process_vmlinux_post_ast(
    elem_type_class,
    llvm_handler,
    handler: DependencyHandler,
    processing_stack=None,
):
    # Initialize processing stack on first call
    if processing_stack is None:
        processing_stack = set()
    symbols_in_module, imported_module = get_module_symbols("vmlinux")

    current_symbol_name = elem_type_class.__name__
    logger.info(f"Begin {current_symbol_name} Processing")
    field_table: Dict[str, list] = {}
    is_complex_type = False
    containing_type: Optional[Any] = None
    ctype_complex_type: Optional[Any] = None
    type_length: Optional[int] = None
    module_name = getattr(elem_type_class, "__module__", None)

    # Check if already processed
    if handler.has_node(current_symbol_name):
        logger.debug(f"Node {current_symbol_name} already processed and ready")
        return True

    # XXX:Check its use. It's probably not being used.
    if current_symbol_name in processing_stack:
        logger.debug(
            f"Dependency already in processing stack for {current_symbol_name}, skipping"
        )
        return True

    processing_stack.add(current_symbol_name)

    if module_name == "vmlinux":
        if hasattr(elem_type_class, "_type_"):
            pass
        else:
            new_dep_node = DependencyNode(name=current_symbol_name)

            # elem_type_class is the actual vmlinux struct/class
            new_dep_node.set_ctype_struct(elem_type_class)

            handler.add_node(new_dep_node)
            class_obj = getattr(imported_module, current_symbol_name)
            # Inspect the class fields
            if hasattr(class_obj, "_fields_"):
                for field_elem in class_obj._fields_:
                    field_name: str = ""
                    field_type: Optional[Any] = None
                    bitfield_size: Optional[int] = None
                    if len(field_elem) == 2:
                        field_name, field_type = field_elem
                    elif len(field_elem) == 3:
                        field_name, field_type, bitfield_size = field_elem
                    field_table[field_name] = [field_type, bitfield_size]
            elif hasattr(class_obj, "__annotations__"):
                for field_elem in class_obj.__annotations__.items():
                    if len(field_elem) == 2:
                        field_name, field_type = field_elem
                        bitfield_size = None
                    elif len(field_elem) == 3:
                        field_name, field_type, bitfield_size = field_elem
                    else:
                        raise ValueError(
                            "Number of fields in items() of class object unexpected"
                        )
                    field_table[field_name] = [field_type, bitfield_size]
            else:
                raise TypeError("Could not get required class and definition")

            logger.debug(f"Extracted fields for {current_symbol_name}: {field_table}")
            for elem in field_table.items():
                elem_name, elem_temp_list = elem
                [elem_type, elem_bitfield_size] = elem_temp_list
                local_module_name = getattr(elem_type, "__module__", None)
                new_dep_node.add_field(elem_name, elem_type, ready=False)

                if local_module_name == ctypes.__name__:
                    # TODO: need to process pointer to ctype and also CFUNCTYPES here recursively. Current processing is a single dereference
                    new_dep_node.set_field_bitfield_size(elem_name, elem_bitfield_size)

                    # Process pointer to ctype
                    if isinstance(elem_type, type) and issubclass(
                        elem_type, ctypes._Pointer
                    ):
                        # Get the pointed-to type
                        pointed_type = elem_type._type_
                        logger.debug(f"Found pointer to type: {pointed_type}")
                        new_dep_node.set_field_containing_type(elem_name, pointed_type)
                        new_dep_node.set_field_ctype_complex_type(
                            elem_name, ctypes._Pointer
                        )
                        new_dep_node.set_field_ready(elem_name, is_ready=True)

                    # Process function pointers (CFUNCTYPE)
                    elif hasattr(elem_type, "_restype_") and hasattr(
                        elem_type, "_argtypes_"
                    ):
                        # This is a CFUNCTYPE or similar
                        logger.info(
                            f"Function pointer detected for {elem_name} with return type {elem_type._restype_} and arguments {elem_type._argtypes_}"
                        )
                        # Set the field as ready but mark it with special handling
                        new_dep_node.set_field_ctype_complex_type(
                            elem_name, ctypes.CFUNCTYPE
                        )
                        new_dep_node.set_field_ready(elem_name, is_ready=True)
                        logger.warning(
                            "Blindly processing CFUNCTYPE ctypes to ensure compilation. Unsupported"
                        )

                    else:
                        # Regular ctype
                        new_dep_node.set_field_ready(elem_name, is_ready=True)
                        logger.debug(
                            f"Field {elem_name} is direct ctypes type: {elem_type}"
                        )
                elif local_module_name == "vmlinux":
                    new_dep_node.set_field_bitfield_size(elem_name, elem_bitfield_size)
                    logger.debug(
                        f"Processing vmlinux field: {elem_name}, type: {elem_type}"
                    )
                    if hasattr(elem_type, "_type_"):
                        is_complex_type = True
                        containing_type = elem_type._type_
                        if hasattr(elem_type, "_length_") and is_complex_type:
                            type_length = elem_type._length_

                        if containing_type.__module__ == "vmlinux":
                            new_dep_node.add_dependent(
                                elem_type._type_.__name__
                                if hasattr(elem_type._type_, "__name__")
                                else str(elem_type._type_)
                            )
                        elif containing_type.__module__ == ctypes.__name__:
                            if isinstance(elem_type, type):
                                if issubclass(elem_type, ctypes.Array):
                                    ctype_complex_type = ctypes.Array
                                elif issubclass(elem_type, ctypes._Pointer):
                                    ctype_complex_type = ctypes._Pointer
                                else:
                                    raise ImportError(
                                        "Non Array and Pointer type ctype imports not supported in current version"
                                    )
                            else:
                                raise TypeError("Unsupported ctypes subclass")
                        else:
                            raise ImportError(
                                f"Unsupported module of {containing_type}"
                            )
                        logger.debug(
                            f"{containing_type} containing type of parent {elem_name} with {elem_type} and ctype {ctype_complex_type} and length {type_length}"
                        )
                        new_dep_node.set_field_containing_type(
                            elem_name, containing_type
                        )
                        new_dep_node.set_field_type_size(elem_name, type_length)
                        new_dep_node.set_field_ctype_complex_type(
                            elem_name, ctype_complex_type
                        )
                        new_dep_node.set_field_type(elem_name, elem_type)
                        if containing_type.__module__ == "vmlinux":
                            containing_type_name = (
                                containing_type.__name__
                                if hasattr(containing_type, "__name__")
                                else str(containing_type)
                            )

                            # Check for self-reference or already processed
                            if containing_type_name == current_symbol_name:
                                # Self-referential pointer
                                logger.debug(
                                    f"Self-referential pointer in {current_symbol_name}.{elem_name}"
                                )
                                new_dep_node.set_field_ready(elem_name, True)
                            elif handler.has_node(containing_type_name):
                                # Already processed
                                logger.debug(
                                    f"Reusing already processed {containing_type_name}"
                                )
                                new_dep_node.set_field_ready(elem_name, True)
                            else:
                                # Process recursively - THIS WAS MISSING
                                new_dep_node.add_dependent(containing_type_name)
                                process_vmlinux_post_ast(
                                    containing_type,
                                    llvm_handler,
                                    handler,
                                    processing_stack,
                                )
                                new_dep_node.set_field_ready(elem_name, True)
                        elif containing_type.__module__ == ctypes.__name__:
                            logger.debug(f"Processing ctype internal{containing_type}")
                            new_dep_node.set_field_ready(elem_name, True)
                        else:
                            raise TypeError(
                                "Module not supported in recursive resolution"
                            )
                    else:
                        new_dep_node.add_dependent(
                            elem_type.__name__
                            if hasattr(elem_type, "__name__")
                            else str(elem_type)
                        )
                        process_vmlinux_post_ast(
                            elem_type,
                            llvm_handler,
                            handler,
                            processing_stack,
                        )
                        new_dep_node.set_field_ready(elem_name, True)
                else:
                    raise ValueError(
                        f"{elem_name} with type {elem_type} from module {module_name} not supported in recursive resolver"
                    )

    else:
        raise ImportError("UNSUPPORTED Module")

    logger.info(
        f"{current_symbol_name} processed and handler readiness {handler.is_ready}"
    )
    return True
