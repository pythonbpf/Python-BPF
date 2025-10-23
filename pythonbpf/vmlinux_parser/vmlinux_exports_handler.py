import logging
from llvmlite import ir

from pythonbpf.vmlinux_parser.assignment_info import AssignmentType

logger = logging.getLogger(__name__)


class VmlinuxHandler:
    """Handler for vmlinux-related operations"""

    _instance = None

    @classmethod
    def get_instance(cls):
        """Get the singleton instance"""
        if cls._instance is None:
            logger.warning("VmlinuxHandler used before initialization")
            return None
        return cls._instance

    @classmethod
    def initialize(cls, vmlinux_symtab):
        """Initialize the handler with vmlinux symbol table"""
        cls._instance = cls(vmlinux_symtab)
        return cls._instance

    def __init__(self, vmlinux_symtab):
        """Initialize with vmlinux symbol table"""
        self.vmlinux_symtab = vmlinux_symtab
        logger.info(
            f"VmlinuxHandler initialized with {len(vmlinux_symtab) if vmlinux_symtab else 0} symbols"
        )

    def is_vmlinux_enum(self, name):
        """Check if name is a vmlinux enum constant"""
        return (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name]["value_type"] == AssignmentType.CONSTANT
        )

    def get_vmlinux_struct_type(self, name):
        """Check if name is a vmlinux struct type"""
        if (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name]["value_type"] == AssignmentType.STRUCT
        ):
            return self.vmlinux_symtab[name]["python_type"]
        else:
            raise ValueError(f"{name} is not a vmlinux struct type")

    def is_vmlinux_struct(self, name):
        """Check if name is a vmlinux struct"""
        return (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name]["value_type"] == AssignmentType.STRUCT
        )

    def handle_vmlinux_enum(self, name):
        """Handle vmlinux enum constants by returning LLVM IR constants"""
        if self.is_vmlinux_enum(name):
            value = self.vmlinux_symtab[name]["value"]
            logger.info(f"Resolving vmlinux enum {name} = {value}")
            return ir.Constant(ir.IntType(64), value), ir.IntType(64)
        return None

    def get_vmlinux_enum_value(self, name):
        """Handle vmlinux enum constants by returning LLVM IR constants"""
        if self.is_vmlinux_enum(name):
            value = self.vmlinux_symtab[name]["value"]
            logger.info(f"The value of vmlinux enum {name} = {value}")
            return value
        return None

    def handle_vmlinux_struct(self, struct_name, module, builder):
        """Handle vmlinux struct initializations"""
        if self.is_vmlinux_struct(struct_name):
            # TODO: Implement core-specific struct handling
            # This will be more complex and depends on the BTF information
            logger.info(f"Handling vmlinux struct {struct_name}")
            # Return struct type and allocated pointer
            # This is a stub, actual implementation will be more complex
            return None
        return None

    def handle_vmlinux_struct_field(
        self, struct_var_name, field_name, module, builder, local_sym_tab
    ):
        """Handle access to vmlinux struct fields"""
        if struct_var_name in local_sym_tab:
            var_info = local_sym_tab[struct_var_name]
            logger.info(
                f"Attempting to access field {field_name} of possible vmlinux struct {struct_var_name}"
            )
            # Return pointer to field and field type
            return None
        else:
            raise RuntimeError("Variable accessed not found in symbol table")

    def has_field(self, struct_name, field_name):
        """Check if a vmlinux struct has a specific field"""
        if self.is_vmlinux_struct(struct_name):
            python_type = self.vmlinux_symtab[struct_name]["python_type"]
            return hasattr(python_type, field_name)
        return False

    def get_field_type(self, vmlinux_struct_name, field_name):
        """Get the type of a field in a vmlinux struct"""
        if self.is_vmlinux_struct(vmlinux_struct_name):
            python_type = self.vmlinux_symtab[vmlinux_struct_name]["python_type"]
            if hasattr(python_type, field_name):
                return self.vmlinux_symtab[vmlinux_struct_name]["members"][field_name]
            else:
                raise ValueError(
                    f"Field {field_name} not found in vmlinux struct {vmlinux_struct_name}"
                )
        else:
            raise ValueError(f"{vmlinux_struct_name} is not a vmlinux struct")
