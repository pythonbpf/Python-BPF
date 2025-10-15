import logging
from ..dependency_handler import DependencyHandler
from .debug_info_gen import debug_info_generation
from ..dependency_node import DependencyNode
import llvmlite.ir as ir

logger = logging.getLogger(__name__)


class IRGenerator:
    # get the assignments dict and add this stuff to it.
    def __init__(self, llvm_module, handler: DependencyHandler, assignment=None):
        self.llvm_module = llvm_module
        self.handler: DependencyHandler = handler
        self.generated: list[str] = []
        if not handler.is_ready:
            raise ImportError(
                "Semantic analysis of vmlinux imports failed. Cannot generate IR"
            )
        for struct in handler:
            self.struct_processor(struct)

    def struct_processor(self, struct):
        if struct.name not in self.generated:
            print(f"IR generating for {struct.name}")
            for dependency in struct.depends_on:
                if dependency not in self.generated:
                    dep_node_from_dependency = self.handler[dependency]
                    self.struct_processor(dep_node_from_dependency)
                    self.generated.append(dependency)
            # actual processor logic here after assuming all dependencies are resolved
            # this part cannot yet resolve circular dependencies. Gets stuck on an infinite loop during that.
            self.gen_ir(struct)
            self.generated.append(struct.name)

    def gen_ir(self, struct):
        # TODO: we add the btf_ama attribute by monkey patching in the end of compilation, but once llvmlite
        #  accepts our issue, we will resort to normal accessed attribute based attribute addition
        # currently we generate all possible field accesses for CO-RE and put into the assignment table
        debug_info = debug_info_generation(struct, self.llvm_module)
        field_index = 0
        for field_name, field in struct.fields.items():
            # does not take arrays and similar types into consideration yet.
            field_co_re_name = self._struct_name_generator(struct, field, field_index)
            field_index += 1
            globvar = ir.GlobalVariable(
                self.llvm_module, ir.IntType(64), name=field_co_re_name
            )
            globvar.linkage = "external"
            globvar.set_metadata("llvm.preserve.access.index", debug_info)
        print()

    def _struct_name_generator(
        self, struct: DependencyNode, field, field_index: int
    ) -> str:
        if struct.name.startswith("struct_"):
            name = (
                "llvm."
                + struct.name.removeprefix("struct_")
                + f":0:{field.offset}"
                + "$"
                + f"0:{field_index}"
            )
            return name
        else:
            raise TypeError(
                "Name generation cannot occur due to type name not starting with struct"
            )
