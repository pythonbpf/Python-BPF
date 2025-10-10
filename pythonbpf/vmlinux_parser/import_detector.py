import ast
import logging
import llvmlite.ir as ir
from typing import List, Tuple

logger = logging.getLogger(__name__)


def detect_import_statement(tree: ast.AST) -> List[Tuple[str, str]]:
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
                    # Use alias if provided, otherwise use the original name
                    as_name = alias.asname if alias.asname else alias.name
                    vmlinux_imports.append(("vmlinux", import_name))
                    logger.info(f"Found vmlinux import: {import_name}")

        # Handle "import vmlinux" statements (not typical but should be rejected)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "vmlinux" or alias.name.startswith("vmlinux."):
                    raise SyntaxError(
                        f"Direct import of vmlinux module is not supported. "
                        f"Use 'from vmlinux import <type>' instead."
                    )

    logger.info(f"Total vmlinux imports detected: {len(vmlinux_imports)}")
    return vmlinux_imports

def vmlinux_proc(tree, module):
    import_statements = detect_import_statement(tree)
    logger.info(f"Import statements {import_statements}")
