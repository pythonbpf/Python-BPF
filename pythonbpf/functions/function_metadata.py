import ast


def get_probe_string(func_node):
    """Extract the probe string from the decorator of the function node"""
    # TODO: right now we have the whole string in the section decorator
    # But later we can implement typed tuples for tracepoints and kprobes
    # For helper functions, we return "helper"

    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "bpfglobal":
            return None
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "section" and len(decorator.args) == 1:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
    return "helper"


def is_global_function(func_node):
    """Check if the function is a global"""
    for decorator in func_node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in (
            "map",
            "bpfglobal",
            "struct",
        ):
            return True
    return False


def infer_return_type(func_node: ast.FunctionDef):
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise TypeError("Expected ast.FunctionDef")
    if func_node.returns is not None:
        try:
            return ast.unparse(func_node.returns)
        except Exception:
            node = func_node.returns
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return getattr(node, "attr", type(node).__name__)
            try:
                return str(node)
            except Exception:
                return type(node).__name__
    found_type = None

    def _expr_type(e):
        if e is None:
            return "None"
        if isinstance(e, ast.Constant):
            return type(e.value).__name__
        if isinstance(e, ast.Name):
            return e.id
        if isinstance(e, ast.Call):
            f = e.func
            if isinstance(f, ast.Name):
                return f.id
            if isinstance(f, ast.Attribute):
                try:
                    return ast.unparse(f)
                except Exception:
                    return getattr(f, "attr", type(f).__name__)
            try:
                return ast.unparse(f)
            except Exception:
                return type(f).__name__
        if isinstance(e, ast.Attribute):
            try:
                return ast.unparse(e)
            except Exception:
                return getattr(e, "attr", type(e).__name__)
        try:
            return ast.unparse(e)
        except Exception:
            return type(e).__name__

    for walked_node in ast.walk(func_node):
        if isinstance(walked_node, ast.Return):
            t = _expr_type(walked_node.value)
            if found_type is None:
                found_type = t
            elif found_type != t:
                raise ValueError(f"Conflicting return types: {found_type} vs {t}")
    return found_type or "None"
