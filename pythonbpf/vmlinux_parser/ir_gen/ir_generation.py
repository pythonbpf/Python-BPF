import logging
from pythonbpf.vmlinux_parser.dependency_handler import DependencyHandler

logger = logging.getLogger(__name__)


class IRGenerator:
    def __init__(self, module, handler: DependencyHandler):
        self.module = module
        self.handler: DependencyHandler = handler
        self.generated: list[str] = []
        if not handler.is_ready:
            raise ImportError(
                "Semantic analysis of vmlinux imports failed. Cannot generate IR"
            )
        for struct in handler:
            self.struct_processor(struct)
            print()

    def struct_processor(self, struct):
        if struct.name not in self.generated:
            print(f"IR generating for {struct.name}")
            print(f"Struct is {struct}")
            for dependency in struct.depends_on:
                if dependency not in self.generated:
                    dep_node_from_dependency = self.handler[dependency]
                    self.struct_processor(dep_node_from_dependency)
                    self.generated.append(dependency)
            # write actual processor logic here after assuming all dependencies are resolved
            # this part cannot yet resolve circular dependencies. Gets stuck on an infinite loop during that.
            self.generated.append(struct.name)

    def struct_name_generator(
        self,
    ) -> None:
        pass
