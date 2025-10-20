import ast
import logging
import importlib
import inspect

from .assignment_info import AssignmentInfo, AssignmentType
from .dependency_handler import DependencyHandler
from .ir_gen import IRGenerator
from .class_handler import process_vmlinux_class

logger = logging.getLogger(__name__)


def detect_import_statement(tree: ast.AST) -> list[tuple[str, ast.ImportFrom]]:
    """
    Parse AST and detect import statements from vmlinux.

    Returns a list of tuples (module_name, imported_item) for vmlinux imports.
    Raises SyntaxError for invalid import patterns.

    Args:
        tree: The AST to parse

    Returns:
        List of tuples containing (module_name, imported_item) for each vmlinux import

    Raises:
        SyntaxError: If multiple imports from vmlinux are attempted or import * is used
    """
    vmlinux_imports = []

    for node in ast.walk(tree):
        # Handle "from vmlinux import ..." statements
        if isinstance(node, ast.ImportFrom):
            if node.module == "vmlinux":
                # Check for wildcard import: from vmlinux import *
                if any(alias.name == "*" for alias in node.names):
                    raise SyntaxError(
                        "Wildcard imports from vmlinux are not supported. "
                        "Please import specific types explicitly."
                    )

                # Check for multiple imports: from vmlinux import A, B, C
                if len(node.names) > 1:
                    imported_names = [alias.name for alias in node.names]
                    raise SyntaxError(
                        f"Multiple imports from vmlinux are not supported. "
                        f"Found: {', '.join(imported_names)}. "
                        f"Please use separate import statements for each type."
                    )

                # Check if no specific import is specified (should not happen with valid Python)
                if len(node.names) == 0:
                    raise SyntaxError(
                        "Import from vmlinux must specify at least one type."
                    )

                # Valid single import
                for alias in node.names:
                    import_name = alias.name
                    # Use alias if provided, otherwise use the original name (commented)
                    # as_name = alias.asname if alias.asname else alias.name
                    vmlinux_imports.append(("vmlinux", node))
                    logger.info(f"Found vmlinux import: {import_name}")

        # Handle "import vmlinux" statements (not typical but should be rejected)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "vmlinux" or alias.name.startswith("vmlinux."):
                    raise SyntaxError(
                        "Direct import of vmlinux module is not supported. "
                        "Use 'from vmlinux import <type>' instead."
                    )

    logger.info(f"Total vmlinux imports detected: {len(vmlinux_imports)}")
    return vmlinux_imports


def vmlinux_proc(tree: ast.AST, module):
    import_statements = detect_import_statement(tree)

    # initialise dependency handler
    handler = DependencyHandler()
    # initialise assignment dictionary of name to type
    assignments: dict[str, AssignmentInfo] = {}

    if not import_statements:
        logger.info("No vmlinux imports found")
        return

    # Import vmlinux module directly
    try:
        vmlinux_mod = importlib.import_module("vmlinux")
    except ImportError:
        logger.warning("Could not import vmlinux module")
        return

    source_file = inspect.getsourcefile(vmlinux_mod)
    if source_file is None:
        logger.warning("Cannot find source for vmlinux module")
        return

    with open(source_file, "r") as f:
        mod_ast = ast.parse(f.read(), filename=source_file)

    for import_mod, import_node in import_statements:
        for alias in import_node.names:
            imported_name = alias.name
            found = False
            for mod_node in mod_ast.body:
                if (
                    isinstance(mod_node, ast.ClassDef)
                    and mod_node.name == imported_name
                ):
                    process_vmlinux_class(mod_node, module, handler)
                    found = True
                    break
                if isinstance(mod_node, ast.Assign):
                    for target in mod_node.targets:
                        if isinstance(target, ast.Name) and target.id == imported_name:
                            process_vmlinux_assign(mod_node, module, assignments)
                            found = True
                            break
                if found:
                    break
            if not found:
                logger.info(
                    f"{imported_name} not found as ClassDef or Assign in vmlinux"
                )

    IRGenerator(module, handler, assignments)
    return assignments


def process_vmlinux_assign(node, module, assignments: dict[str, AssignmentInfo]):
    """Process assignments from vmlinux module."""
    # Only handle single-target assignments
    if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        target_name = node.targets[0].id

        # Handle constant value assignments
        if isinstance(node.value, ast.Constant):
            # Fixed: using proper TypedDict creation syntax with named arguments
            assignments[target_name] = AssignmentInfo(
                value_type=AssignmentType.CONSTANT,
                python_type=type(node.value.value),
                value=node.value.value,
                pointer_level=None,
                signature=None,
                members=None,
            )
            logger.info(
                f"Added assignment: {target_name} = {node.value.value!r} of type {type(node.value.value)}"
            )

        # Handle other assignment types that we may need to support
        else:
            logger.warning(
                f"Unsupported assignment type for {target_name}: {ast.dump(node.value)}"
            )
    else:
        raise ValueError("Not a simple assignment")
