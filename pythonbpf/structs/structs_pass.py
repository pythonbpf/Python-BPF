import ast
import logging
from llvmlite import ir
from pythonbpf.type_deducer import ctypes_to_ir
from .struct_type import StructType

logger = logging.getLogger(__name__)

# TODO: Shall we allow the following syntax:
# struct MyStruct:
#     field1: int
#     field2: str(32)
# Where int is mapped to c_uint64?
# Shall we just int64, int32 and uint32 similarly?


def structs_proc(tree, module, chunks):
    """Process all class definitions to find BPF structs"""
    structs_sym_tab = {}
    for cls_node in chunks:
        if is_bpf_struct(cls_node):
            logger.info(f"Found BPF struct: {cls_node.name}")
            struct_info = process_bpf_struct(cls_node, module)
            structs_sym_tab[cls_node.name] = struct_info
    return structs_sym_tab


def is_bpf_struct(cls_node):
    """
    Check if a class node is decorated with @struct.
    
    Args:
        cls_node: The AST class node to check
    
    Returns:
        True if the class is decorated with @struct, False otherwise
    """
    return any(
        isinstance(decorator, ast.Name) and decorator.id == "struct"
        for decorator in cls_node.decorator_list
    )


def process_bpf_struct(cls_node, module):
    """
    Process a single BPF struct definition and create its LLVM IR representation.
    
    Args:
        cls_node: The AST class node representing the struct
        module: The LLVM IR module (not used in current implementation)
    
    Returns:
        A StructType object containing the struct's type information
    """

    fields = parse_struct_fields(cls_node)
    field_types = list(fields.values())
    total_size = calc_struct_size(field_types)
    struct_type = ir.LiteralStructType(field_types)
    logger.info(f"Created struct {cls_node.name} with fields {fields.keys()}")
    return StructType(struct_type, fields, total_size)


def parse_struct_fields(cls_node):
    """
    Parse fields of a struct class node.
    
    Args:
        cls_node: The AST class node representing the struct
    
    Returns:
        A dictionary mapping field names to their LLVM IR types
    
    Raises:
        TypeError: If a field has an unsupported type annotation
    """
    fields = {}

    for item in cls_node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields[item.target.id] = get_type_from_ann(item.annotation)
        else:
            logger.error(f"Unsupported struct field: {ast.dump(item)}")
            raise TypeError(f"Unsupported field in {ast.dump(cls_node)}")
    return fields


def get_type_from_ann(annotation):
    """
    Convert an AST annotation node to an LLVM IR type for struct fields.
    
    Args:
        annotation: The AST annotation node (e.g., c_int64, str(32))
    
    Returns:
        The corresponding LLVM IR type
    
    Raises:
        TypeError: If the annotation type is not supported
    """
    if isinstance(annotation, ast.Call) and isinstance(annotation.func, ast.Name):
        if annotation.func.id == "str":
            # Char array
            # Assumes constant integer argument
            length = annotation.args[0].value
            return ir.ArrayType(ir.IntType(8), length)
    elif isinstance(annotation, ast.Name):
        # Int type, written as c_int64, c_uint32, etc.
        return ctypes_to_ir(annotation.id)

    raise TypeError(f"Unsupported annotation type: {ast.dump(annotation)}")


def calc_struct_size(field_types):
    """
    Calculate total size of the struct with alignment and padding.
    
    Args:
        field_types: List of LLVM IR types for each field
    
    Returns:
        The total size of the struct in bytes
    """
    curr_offset = 0
    for ftype in field_types:
        if isinstance(ftype, ir.IntType):
            fsize = ftype.width // 8
            alignment = fsize
        elif isinstance(ftype, ir.ArrayType):
            fsize = ftype.count * (ftype.element.width // 8)
            alignment = ftype.element.width // 8
        elif isinstance(ftype, ir.PointerType):
            # We won't encounter this rn, but for the future
            fsize = 8
            alignment = 8
        else:
            raise TypeError(f"Unsupported field type: {ftype}")

        padding = (alignment - (curr_offset % alignment)) % alignment
        curr_offset += padding + fsize

    final_padding = (8 - (curr_offset % 8)) % 8
    return curr_offset + final_padding
