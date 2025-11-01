import logging
from typing import Any

from llvmlite import ir

from pythonbpf.local_symbol import LocalSymbol
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
            and self.vmlinux_symtab[name].value_type == AssignmentType.CONSTANT
        )

    def get_struct_debug_info(self, name: str) -> Any:
        if (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name].value_type == AssignmentType.STRUCT
        ):
            return self.vmlinux_symtab[name].debug_info
        else:
            raise ValueError(f"{name} is not a vmlinux struct type")

    def get_vmlinux_struct_type(self, name):
        """Check if name is a vmlinux struct type"""
        if (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name].value_type == AssignmentType.STRUCT
        ):
            return self.vmlinux_symtab[name].python_type
        else:
            raise ValueError(f"{name} is not a vmlinux struct type")

    def is_vmlinux_struct(self, name):
        """Check if name is a vmlinux struct"""
        return (
            name in self.vmlinux_symtab
            and self.vmlinux_symtab[name].value_type == AssignmentType.STRUCT
        )

    def handle_vmlinux_enum(self, name):
        """Handle vmlinux enum constants by returning LLVM IR constants"""
        if self.is_vmlinux_enum(name):
            value = self.vmlinux_symtab[name].value
            logger.info(f"Resolving vmlinux enum {name} = {value}")
            return ir.Constant(ir.IntType(64), value), ir.IntType(64)
        return None

    def get_vmlinux_enum_value(self, name):
        """Handle vmlinux enum constants by returning LLVM IR constants"""
        if self.is_vmlinux_enum(name):
            value = self.vmlinux_symtab[name].value
            logger.info(f"The value of vmlinux enum {name} = {value}")
            return value
        return None

    def handle_vmlinux_struct_field(
        self, struct_var_name, field_name, module, builder, local_sym_tab
    ):
        """Handle access to vmlinux struct fields"""
        if struct_var_name in local_sym_tab:
            var_info: LocalSymbol = local_sym_tab[struct_var_name]
            logger.info(
                f"Attempting to access field {field_name} of possible vmlinux struct {struct_var_name}"
            )
            python_type: type = var_info.metadata
            globvar_ir, field_data = self.get_field_type(
                python_type.__name__, field_name
            )
            builder.function.args[0].type = ir.PointerType(ir.IntType(8))
            print(builder.function.args[0])
            field_ptr = self.load_ctx_field(
                builder, builder.function.args[0], globvar_ir
            )
            print(field_ptr)
            # Return pointer to field and field type
            return field_ptr, field_data
        else:
            raise RuntimeError("Variable accessed not found in symbol table")

    @staticmethod
    def load_ctx_field(builder, ctx_arg, offset_global):
        """
        Generate LLVM IR to load a field from BPF context using offset.

        Args:
            builder: llvmlite IRBuilder instance
            ctx_arg: The context pointer argument (ptr/i8*)
            offset_global: Global variable containing the field offset (i64)

        Returns:
            The loaded value (i64 register)
        """

        # Load the offset value
        offset = builder.load(offset_global)

        # Ensure ctx_arg is treated as i8* (byte pointer)
        i8_ptr_type = ir.PointerType()

        # Cast ctx_arg to i8* if it isn't already
        if str(ctx_arg.type) != str(i8_ptr_type):
            ctx_i8_ptr = builder.bitcast(ctx_arg, i8_ptr_type)
        else:
            ctx_i8_ptr = ctx_arg

        # GEP with explicit type - this is the key fix
        field_ptr = builder.gep(
            ctx_i8_ptr,
            [offset],
            inbounds=False,
        )

        # Get or declare the BPF passthrough intrinsic
        module = builder.function.module

        try:
            passthrough_fn = module.globals.get("llvm.bpf.passthrough.p0.p0")
            if passthrough_fn is None:
                raise KeyError
        except (KeyError, AttributeError):
            passthrough_type = ir.FunctionType(
                i8_ptr_type,
                [ir.IntType(32), i8_ptr_type],
            )
            passthrough_fn = ir.Function(
                module,
                passthrough_type,
                name="llvm.bpf.passthrough.p0.p0",
            )

        # Call passthrough to satisfy BPF verifier
        verified_ptr = builder.call(
            passthrough_fn, [ir.Constant(ir.IntType(32), 0), field_ptr], tail=True
        )

        # Bitcast to i64* (assuming field is 64-bit, adjust if needed)
        i64_ptr_type = ir.PointerType(ir.IntType(64))
        typed_ptr = builder.bitcast(verified_ptr, i64_ptr_type)

        # Load and return the value
        value = builder.load(typed_ptr)

        return value

    def has_field(self, struct_name, field_name):
        """Check if a vmlinux struct has a specific field"""
        if self.is_vmlinux_struct(struct_name):
            python_type = self.vmlinux_symtab[struct_name].python_type
            return hasattr(python_type, field_name)
        return False

    def get_field_type(self, vmlinux_struct_name, field_name):
        """Get the type of a field in a vmlinux struct"""
        if self.is_vmlinux_struct(vmlinux_struct_name):
            python_type = self.vmlinux_symtab[vmlinux_struct_name].python_type
            if hasattr(python_type, field_name):
                return self.vmlinux_symtab[vmlinux_struct_name].members[field_name]
            else:
                raise ValueError(
                    f"Field {field_name} not found in vmlinux struct {vmlinux_struct_name}"
                )
        else:
            raise ValueError(f"{vmlinux_struct_name} is not a vmlinux struct")

    def get_field_index(self, vmlinux_struct_name, field_name):
        """Get the type of a field in a vmlinux struct"""
        if self.is_vmlinux_struct(vmlinux_struct_name):
            python_type = self.vmlinux_symtab[vmlinux_struct_name].python_type
            if hasattr(python_type, field_name):
                return list(
                    self.vmlinux_symtab[vmlinux_struct_name].members.keys()
                ).index(field_name)
            else:
                raise ValueError(
                    f"Field {field_name} not found in vmlinux struct {vmlinux_struct_name}"
                )
        else:
            raise ValueError(f"{vmlinux_struct_name} is not a vmlinux struct")
