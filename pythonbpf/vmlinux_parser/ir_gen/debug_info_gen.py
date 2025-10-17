from pythonbpf.debuginfo import DebugInfoGenerator
from ..dependency_node import DependencyNode


def debug_info_generation(
    struct: DependencyNode, llvm_module, generated_debug_info: list
):
    generator = DebugInfoGenerator(llvm_module)
    members = []
    uint32type = generator.get_uint32_type()
    for field_name, field in struct.fields.items():
        members.append(generator.create_struct_member(field_name, uint32type, field.offset))

    struct_type = generator.create_struct_type(members, struct.__sizeof__(), is_distinct=True)

    global_var = generator.create_global_var_debug_info(
        struct.name, struct_type, is_local=False
    )

    return global_var
