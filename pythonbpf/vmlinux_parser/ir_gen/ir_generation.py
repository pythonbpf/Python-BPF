import ctypes
import logging

from ..assignment_info import AssignmentInfo, AssignmentType
from ..dependency_handler import DependencyHandler
from .debug_info_gen import debug_info_generation
from ..dependency_node import DependencyNode
import llvmlite.ir as ir

logger = logging.getLogger(__name__)


class IRGenerator:
    # get the assignments dict and add this stuff to it.
    def __init__(self, llvm_module, handler: DependencyHandler, assignments):
        self.llvm_module = llvm_module
        self.handler: DependencyHandler = handler
        self.generated: list[str] = []
        self.generated_debug_info: list = []
        # Use struct_name and field_name as key instead of Field object
        self.generated_field_names: dict[str, dict[str, ir.GlobalVariable]] = {}
        self.assignments: dict[str, AssignmentInfo] = assignments
        if not handler.is_ready:
            raise ImportError(
                "Semantic analysis of vmlinux imports failed. Cannot generate IR"
            )
        for struct in handler:
            self.struct_processor(struct)

    def struct_processor(self, struct, processing_stack=None):
        # Initialize processing stack on first call
        if processing_stack is None:
            processing_stack = set()

        # If already generated, skip
        if struct.name in self.generated:
            return

        # Detect circular dependency
        if struct.name in processing_stack:
            logger.info(
                f"Circular dependency detected for {struct.name}, skipping recursive processing"
            )
            # For circular dependencies, we can either:
            # 1. Use forward declarations (opaque pointers)
            # 2. Mark as incomplete and process later
            # 3. Generate a placeholder type
            # Here we'll just skip and let it be processed in its own call
            return

        logger.info(f"IR generating for {struct.name}")

        # Add to processing stack before processing dependencies
        processing_stack.add(struct.name)

        try:
            # Process all dependencies first
            if struct.depends_on is None:
                pass
            else:
                for dependency in struct.depends_on:
                    if dependency not in self.generated:
                        # Check if dependency exists in handler
                        if dependency in self.handler.nodes:
                            dep_node_from_dependency = self.handler[dependency]
                            # Pass the processing_stack down to track circular refs
                            self.struct_processor(
                                dep_node_from_dependency, processing_stack
                            )
                        else:
                            raise RuntimeError(
                                f"Warning: Dependency {dependency} not found in handler"
                            )

            # Generate IR first to populate field names
            self.generated_debug_info.append(
                (struct, self.gen_ir(struct, self.generated_debug_info))
            )

            # Fill the assignments dictionary with struct information
            if struct.name not in self.assignments:
                # Create a members dictionary for AssignmentInfo
                members_dict = {}
                for field_name, field in struct.fields.items():
                    # Get the generated field name from our dictionary, or use field_name if not found
                    if (
                        struct.name in self.generated_field_names
                        and field_name in self.generated_field_names[struct.name]
                    ):
                        field_global_variable = self.generated_field_names[struct.name][
                            field_name
                        ]
                        members_dict[field_name] = (field_global_variable, field)
                    else:
                        raise ValueError(
                            f"llvm global name not found for struct field {field_name}"
                        )
                        # members_dict[field_name] = (field_name, field)

                # Add struct to assignments dictionary
                self.assignments[struct.name] = AssignmentInfo(
                    value_type=AssignmentType.STRUCT,
                    python_type=struct.ctype_struct,
                    value=None,
                    pointer_level=None,
                    signature=None,
                    members=members_dict,
                )
                logger.info(f"Added struct assignment info for {struct.name}")

            self.generated.append(struct.name)

        finally:
            # Remove from processing stack after we're done
            processing_stack.discard(struct.name)

    def gen_ir(self, struct, generated_debug_info):
        # TODO: we add the btf_ama attribute by monkey patching in the end of compilation, but once llvmlite
        #  accepts our issue, we will resort to normal accessed attribute based attribute addition
        # currently we generate all possible field accesses for CO-RE and put into the assignment table
        debug_info = debug_info_generation(
            struct, self.llvm_module, generated_debug_info
        )
        field_index = 0

        # Make sure the struct has an entry in our field names dictionary
        if struct.name not in self.generated_field_names:
            self.generated_field_names[struct.name] = {}

        for field_name, field in struct.fields.items():
            # does not take arrays and similar types into consideration yet.
            if field.ctype_complex_type is not None and issubclass(
                field.ctype_complex_type, ctypes.Array
            ):
                array_size = field.type_size
                containing_type = field.containing_type
                if containing_type.__module__ == ctypes.__name__:
                    containing_type_size = ctypes.sizeof(containing_type)
                    if array_size == 0:
                        field_co_re_name = self._struct_name_generator(
                            struct, field, field_index, True, 0, containing_type_size
                        )
                        globvar = ir.GlobalVariable(
                            self.llvm_module, ir.IntType(64), name=field_co_re_name
                        )
                        globvar.linkage = "external"
                        globvar.set_metadata("llvm.preserve.access.index", debug_info)
                        self.generated_field_names[struct.name][field_name] = globvar
                        field_index += 1
                        continue
                    for i in range(0, array_size):
                        field_co_re_name = self._struct_name_generator(
                            struct, field, field_index, True, i, containing_type_size
                        )
                        globvar = ir.GlobalVariable(
                            self.llvm_module, ir.IntType(64), name=field_co_re_name
                        )
                        globvar.linkage = "external"
                        globvar.set_metadata("llvm.preserve.access.index", debug_info)
                        self.generated_field_names[struct.name][field_name] = globvar
                    field_index += 1
            elif field.type_size is not None:
                array_size = field.type_size
                containing_type = field.containing_type
                if containing_type.__module__ == "vmlinux":
                    containing_type_size = self.handler[
                        containing_type.__name__
                    ].current_offset
                    for i in range(0, array_size):
                        field_co_re_name = self._struct_name_generator(
                            struct, field, field_index, True, i, containing_type_size
                        )
                        globvar = ir.GlobalVariable(
                            self.llvm_module, ir.IntType(64), name=field_co_re_name
                        )
                        globvar.linkage = "external"
                        globvar.set_metadata("llvm.preserve.access.index", debug_info)
                        self.generated_field_names[struct.name][field_name] = globvar
                    field_index += 1
            else:
                field_co_re_name = self._struct_name_generator(
                    struct, field, field_index
                )
                field_index += 1
                globvar = ir.GlobalVariable(
                    self.llvm_module, ir.IntType(64), name=field_co_re_name
                )
                globvar.linkage = "external"
                globvar.set_metadata("llvm.preserve.access.index", debug_info)
                self.generated_field_names[struct.name][field_name] = globvar
        return debug_info

    def _struct_name_generator(
        self,
        struct: DependencyNode,
        field,
        field_index: int,
        is_indexed: bool = False,
        index: int = 0,
        containing_type_size: int = 0,
    ) -> str:
        # TODO: Does not support Unions as well as recursive pointer and array type naming
        if is_indexed:
            name = (
                "llvm."
                + struct.name.removeprefix("struct_")
                + f":0:{field.offset + index * containing_type_size}"
                + "$"
                + f"0:{field_index}:{index}"
            )
            return name
        elif struct.name.startswith("struct_"):
            name = (
                "llvm."
                + struct.name.removeprefix("struct_")
                + f":0:{field.offset}"
                + "$"
                + f"0:{field_index}"
            )
            return name
        else:
            print(self.handler[struct.name])
            raise TypeError(
                "Name generation cannot occur due to type name not starting with struct"
            )
