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

def process_vmlinux_class(node, llvm_module, handler: DependencyHandler):
    symbols_in_module, imported_module = get_module_symbols("vmlinux")
    if node.name in symbols_in_module:
        vmlinux_type = getattr(imported_module, node.name)
        process_vmlinux_post_ast(vmlinux_type, llvm_module, handler)
    else:
        raise ImportError(f"{node.name} not in vmlinux")

# Recursive function that gets all the dependent classes and adds them to handler
def process_vmlinux_post_ast(node, llvm_module, handler: DependencyHandler, processing_stack=None):
    """
    Recursively process vmlinux classes and their dependencies.

    Args:
        node: The class/type to process
        llvm_module: The LLVM module context
        handler: DependencyHandler to track all nodes
        processing_stack: Set of currently processing nodes to detect cycles
    """
    # Initialize processing stack on first call
    if processing_stack is None:
        processing_stack = set()

    symbols_in_module, imported_module = get_module_symbols("vmlinux")

    # Handle both node objects and type objects
    if hasattr(node, "name"):
        current_symbol_name = node.name
    elif hasattr(node, "__name__"):
        current_symbol_name = node.__name__
    else:
        current_symbol_name = str(node)

    if current_symbol_name not in symbols_in_module:
        raise ImportError(f"{current_symbol_name} not present in module vmlinux")

    # Check if we're already processing this node (circular dependency)
    if current_symbol_name in processing_stack:
        logger.debug(f"Circular dependency detected for {current_symbol_name}, skipping")
        return True

    # Check if already processed
    if handler.has_node(current_symbol_name):
        existing_node = handler.get_node(current_symbol_name)
        # If the node exists and is ready, we're done
        if existing_node and existing_node.is_ready:
            logger.info(f"Node {current_symbol_name} already processed and ready")
            return True

    logger.info(f"Resolving vmlinux class {current_symbol_name}")
    logger.debug(
        f"Current handler state: {handler.is_ready} readiness and {handler.get_all_nodes()} all nodes"
    )

    # Add to processing stack to detect cycles
    processing_stack.add(current_symbol_name)

    try:
        field_table = {}  # should contain the field and it's type.

        # Get the class object from the module
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

        logger.debug(f"Extracted fields for {current_symbol_name}: {field_table}")

        # Create or get the node
        if handler.has_node(current_symbol_name):
            new_dep_node = handler.get_node(current_symbol_name)
        else:
            new_dep_node = DependencyNode(name=current_symbol_name)
            handler.add_node(new_dep_node)

        # Process each field
        for elem_name, elem_type in field_table.items():
            module_name = getattr(elem_type, "__module__", None)

            if module_name == ctypes.__name__:
                # Simple ctypes - mark as ready immediately
                new_dep_node.add_field(elem_name, elem_type, ready=True)

            elif module_name == "vmlinux":
                # Complex vmlinux type - needs recursive processing
                new_dep_node.add_field(elem_name, elem_type, ready=False)
                logger.debug(f"Processing vmlinux field: {elem_name}, type: {elem_type}")

                identify_ctypes_type(elem_name, elem_type, new_dep_node)

                # Determine the actual symbol to process
                symbol_name = (
                    elem_type.__name__
                    if hasattr(elem_type, "__name__")
                    else str(elem_type)
                )
                vmlinux_symbol = None

                # Handle pointers/arrays to other types
                if hasattr(elem_type, "_type_"):
                    containing_module_name = getattr(
                        (elem_type._type_), "__module__", None
                    )
                    if containing_module_name == ctypes.__name__:
                        # Pointer/Array to ctypes - mark as ready
                        new_dep_node.set_field_ready(elem_name, True)
                        continue
                    elif containing_module_name == "vmlinux":
                        # Pointer/Array to vmlinux type
                        symbol_name = (
                            (elem_type._type_).__name__
                            if hasattr((elem_type._type_), "__name__")
                            else str(elem_type._type_)
                        )

                        # Self-referential check
                        if symbol_name == current_symbol_name:
                            logger.debug(f"Self-referential field {elem_name} in {current_symbol_name}")
                            # For pointers to self, we can mark as ready since the type is being defined
                            new_dep_node.set_field_ready(elem_name, True)
                            continue

                        vmlinux_symbol = getattr(imported_module, symbol_name)
                else:
                    # Direct vmlinux type (not pointer/array)
                    vmlinux_symbol = getattr(imported_module, symbol_name)

                # Recursively process the dependency
                if vmlinux_symbol is not None:
                    if process_vmlinux_post_ast(vmlinux_symbol, llvm_module, handler, processing_stack):
                        new_dep_node.set_field_ready(elem_name, True)
            else:
                raise ValueError(
                    f"{elem_name} with type {elem_type} not supported in recursive resolver"
                )

        logger.info(f"Successfully processed node: {current_symbol_name}")
        return True

    finally:
        # Remove from processing stack when done
        processing_stack.discard(current_symbol_name)


def identify_ctypes_type(elem_name, elem_type, new_dep_node: DependencyNode):
    if isinstance(elem_type, type):
        if issubclass(elem_type, ctypes.Array):
            new_dep_node.set_field_type(elem_name, ctypes.Array)
            new_dep_node.set_field_containing_type(elem_name, elem_type._type_)
            new_dep_node.set_field_type_size(elem_name, elem_type._length_)
        elif issubclass(elem_type, ctypes._Pointer):
            new_dep_node.set_field_type(elem_name, ctypes._Pointer)
            new_dep_node.set_field_containing_type(elem_name, elem_type._type_)
    else:
        raise TypeError("Instance sent instead of Class")
