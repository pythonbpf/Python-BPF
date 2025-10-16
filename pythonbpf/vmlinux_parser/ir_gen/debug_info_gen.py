from pythonbpf.debuginfo import DebugInfoGenerator


def debug_info_generation(struct, llvm_module):
    generator = DebugInfoGenerator(llvm_module)
    # this is sample debug info generation
    # i64type = generator.get_uint64_type()

    struct_type = generator.create_struct_type([], 64 * 4, is_distinct=True)

    global_var = generator.create_global_var_debug_info(
        struct.name, struct_type, is_local=False
    )

    return global_var
