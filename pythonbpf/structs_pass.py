import ast
from llvmlite import ir
from .type_deducer import ctypes_to_ir
from . import dwarf_constants as dc

structs_sym_tab = {}


def structs_proc(tree, module, chunks):
    for cls_node in chunks:
        # Check if this class is a struct
        is_struct = False
        for decorator in cls_node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "struct":
                is_struct = True
                break
        if is_struct:
            print(f"Found BPF struct: {cls_node.name}")
            process_bpf_struct(cls_node, module)
            continue
    return structs_sym_tab


def process_bpf_struct(cls_node, module):
    struct_name = cls_node.name
    field_names = []
    field_types = []

    for item in cls_node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            print(f"Field: {item.target.id}, Type: "
                  f"{ast.dump(item.annotation)}")
            field_names.append(item.target.id)
            if isinstance(item.annotation, ast.Call) and isinstance(item.annotation.func, ast.Name) and item.annotation.func.id == "str":
                # This is a char array with fixed length
                # TODO: For now assuming str is always called with constant
                field_types.append(ir.ArrayType(
                    ir.IntType(8), item.annotation.args[0].value))
            else:
                field_types.append(ctypes_to_ir(item.annotation.id))

    curr_offset = 0
    for ftype in field_types:
        if isinstance(ftype, ir.IntType):
            fsize = ftype.width // 8
            alignment = fsize
        elif isinstance(ftype, ir.ArrayType):
            fsize = ftype.count * (ftype.element.width // 8)
            alignment = ftype.element.width // 8
        elif isinstance(ftype, ir.PointerType):
            fsize = 8
            alignment = 8
        else:
            print(f"Unsupported field type in struct {struct_name}")
            return
        padding = (alignment - (curr_offset % alignment)) % alignment
        curr_offset += padding
        curr_offset += fsize
    final_padding = (8 - (curr_offset % 8)) % 8
    total_size = curr_offset + final_padding

    struct_type = ir.LiteralStructType(field_types)
    structs_sym_tab[struct_name] = {
        "type": struct_type,
        "fields": {name: idx for idx, name in enumerate(field_names)},
        "size": total_size,
        "field_types": field_types,
    }
    print(f"Created struct {struct_name} with fields {field_names}")
