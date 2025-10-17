from pythonbpf.debuginfo import DebugInfoGenerator
from ..dependency_node import DependencyNode


def debug_info_generation(
    struct: DependencyNode, llvm_module, generated_debug_info: list
):
    generator = DebugInfoGenerator(llvm_module)
    print("DEBUG1", generated_debug_info)
    for field in struct.fields:
        print("DEBUG", field)

    struct_type = generator.create_struct_type([], 64 * 4, is_distinct=True)

    global_var = generator.create_global_var_debug_info(
        struct.name, struct_type, is_local=False
    )

    return global_var
