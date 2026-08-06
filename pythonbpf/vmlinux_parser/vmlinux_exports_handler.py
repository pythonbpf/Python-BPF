import logging
from typing import Any
import ctypes
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
        """Handle vmlinux.enum constants by returning LLVM IR constants"""
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
            # Check if this is a context field (ctx) or a cast struct
            is_context_field = var_info.var is None

            if is_context_field:
                # Handle context field access (original behavior)
                struct_name = python_type.__name__
                globvar_ir, field_data = self.get_field_type(struct_name, field_name)
                builder.function.args[0].type = ir.PointerType(ir.IntType(8))
                field_ptr = self.load_ctx_field(
                    builder,
                    builder.function.args[0],
                    globvar_ir,
                    field_data,
                    struct_name,
                )
                return field_ptr, field_data
            else:
                # Handle cast struct field access
                struct_name = python_type.__name__
                globvar_ir, field_data = self.get_field_type(struct_name, field_name)

                # Handle cast struct field access (use bpf_probe_read_kernel)
                # Load the struct pointer from the local variable
                struct_ptr = builder.load(var_info.var)

                # Determine the preallocated tmp name that assignment pass should have created
                tmp_name = f"{struct_var_name}_{field_name}_tmp"

                # Use bpf_probe_read_kernel for non-context struct field access
                field_value = self.load_struct_field(
                    builder,
                    struct_ptr,
                    globvar_ir,
                    field_data,
                    struct_name,
                    local_sym_tab,
                    tmp_name,
                )
                # Return field value and field type
                return field_value, field_data
        else:
            raise RuntimeError("Variable accessed not found in symbol table")

    @staticmethod
    def load_struct_field(
        builder,
        struct_ptr_int,
        offset_global,
        field_data,
        struct_name=None,
        local_sym_tab=None,
        tmp_name: str | None = None,
    ):
        """
        Generate LLVM IR to load a field from a regular (non-context) struct using bpf_probe_read_kernel.

        Args:
            builder: llvmlite IRBuilder instance
            struct_ptr_int: The struct pointer as an i64 value (already loaded from alloca)
            offset_global: Global variable containing the field offset (i64)
            field_data: contains data about the field
            struct_name: Name of the struct being accessed (optional)
            local_sym_tab: symbol table (optional) - used to locate preallocated tmp storage
            tmp_name: name of the preallocated temporary storage to use (preferred)
        Returns:
            The loaded value
        """

        # Load the offset value
        offset = builder.load(offset_global)

        # Convert i64 to pointer type (BPF stores pointers as i64)
        i8_ptr_type = ir.PointerType(ir.IntType(8))
        struct_ptr = builder.inttoptr(struct_ptr_int, i8_ptr_type)

        # GEP with offset to get field pointer
        field_ptr = builder.gep(
            struct_ptr,
            [offset],
            inbounds=False,
        )

        # Determine the appropriate field size based on field information
        field_size_bytes = 8  # Default to 8 bytes (64-bit)
        int_width = 64  # Default to 64-bit
        needs_zext = False

        if field_data is not None:
            # Try to determine the size from field metadata
            if field_data.type.__module__ == ctypes.__name__:
                try:
                    field_size_bytes = ctypes.sizeof(field_data.type)
                    field_size_bits = field_size_bytes * 8

                    if field_size_bits in [8, 16, 32, 64]:
                        int_width = field_size_bits
                        logger.info(
                            f"Determined field size: {int_width} bits ({field_size_bytes} bytes)"
                        )

                        # Special handling for struct_xdp_md i32 fields
                        if struct_name == "struct_xdp_md" and int_width == 32:
                            needs_zext = True
                            logger.info(
                                "struct_xdp_md i32 field detected, will zero-extend to i64"
                            )
                    else:
                        logger.warning(
                            f"Unusual field size {field_size_bits} bits, using default 64"
                        )
                except Exception as e:
                    logger.warning(
                        f"Could not determine field size: {e}, using default 64"
                    )

            elif field_data.type.__module__ == "vmlinux":
                # For pointers to structs or complex vmlinux types
                if field_data.ctype_complex_type is not None and issubclass(
                    field_data.ctype_complex_type, ctypes._Pointer
                ):
                    int_width = 64  # Pointers are always 64-bit
                    field_size_bytes = 8
                    logger.info("Field is a pointer type, using 64 bits")
                else:
                    logger.warning("Complex vmlinux field type, using default 64 bits")

        # Use preallocated temporary storage if provided by allocation pass

        local_storage_i8_ptr = None
        if tmp_name and local_sym_tab and tmp_name in local_sym_tab:
            # Expect the tmp to be an alloca created during allocation pass
            tmp_alloca = local_sym_tab[tmp_name].var
            local_storage_i8_ptr = builder.bitcast(tmp_alloca, i8_ptr_type)
        else:
            # Fallback: allocate inline (not ideal, but preserves behavior)
            local_storage = builder.alloca(ir.IntType(int_width))
            local_storage_i8_ptr = builder.bitcast(local_storage, i8_ptr_type)
            logger.warning(f"Temp storage '{tmp_name}' not found. Allocating inline")

        # Use bpf_probe_read_kernel to safely read the field
        # This generates:
        #   %gep = getelementptr i8, ptr %struct_ptr, i64 %offset (already done above as field_ptr)
        #   %passed = tail call ptr @llvm.bpf.passthrough.p0.p0(i32 2, ptr %gep)
        #   %result = call i64 inttoptr (i64 113 to ptr)(ptr %local_storage, i32 %size, ptr %passed)
        from pythonbpf.helper import emit_probe_read_kernel_call

        emit_probe_read_kernel_call(
            builder, local_storage_i8_ptr, field_size_bytes, field_ptr
        )

        # Load the value from local storage
        value = builder.load(
            builder.bitcast(local_storage_i8_ptr, ir.PointerType(ir.IntType(int_width)))
        )

        # Zero-extend i32 to i64 if needed
        if needs_zext:
            value = builder.zext(value, ir.IntType(64))
            logger.info("Zero-extended i32 value to i64")

        return value

    @staticmethod
    def load_ctx_field(builder, ctx_arg, offset_global, field_data, struct_name=None):
        """
        Generate LLVM IR to load a field from BPF context using offset.

        Args:
            builder: llvmlite IRBuilder instance
            ctx_arg: The context pointer argument (ptr/i8*)
            offset_global: Global variable containing the field offset (i64)
            field_data: contains data about the field
            struct_name: Name of the struct being accessed (optional)
        Returns:
            The loaded value (i64 register or appropriately sized)
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

        # Determine the appropriate IR type based on field information
        int_width = 64  # Default to 64-bit
        needs_zext = False  # Track if we need zero-extension for xdp_md

        if field_data is not None:
            # Try to determine the size from field metadata
            if field_data.type.__module__ == ctypes.__name__:
                try:
                    field_size_bytes = ctypes.sizeof(field_data.type)
                    field_size_bits = field_size_bytes * 8

                    if field_size_bits in [8, 16, 32, 64]:
                        int_width = field_size_bits
                        logger.info(f"Determined field size: {int_width} bits")

                        # Special handling for struct_xdp_md i32 fields
                        # Load as i32 but extend to i64 before storing
                        if struct_name == "struct_xdp_md" and int_width == 32:
                            needs_zext = True
                            logger.info(
                                "struct_xdp_md i32 field detected, will zero-extend to i64"
                            )
                    else:
                        logger.warning(
                            f"Unusual field size {field_size_bits} bits, using default 64"
                        )
                except Exception as e:
                    logger.warning(
                        f"Could not determine field size: {e}, using default 64"
                    )

            elif field_data.type.__module__ == "vmlinux":
                # For pointers to structs or complex vmlinux types
                if field_data.ctype_complex_type is not None and issubclass(
                    field_data.ctype_complex_type, ctypes._Pointer
                ):
                    int_width = 64  # Pointers are always 64-bit
                    logger.info("Field is a pointer type, using 64 bits")
                # TODO: Add handling for other complex types (arrays, embedded structs, etc.)
                else:
                    logger.warning("Complex vmlinux field type, using default 64 bits")

        # Bitcast to appropriate pointer type based on determined width
        ptr_type = ir.PointerType(ir.IntType(int_width))

        typed_ptr = builder.bitcast(verified_ptr, ptr_type)

        # Load and return the value
        value = builder.load(typed_ptr)

        # Zero-extend i32 to i64 for struct_xdp_md fields
        if needs_zext:
            value = builder.zext(value, ir.IntType(64))
            logger.info("Zero-extended i32 value to i64 for struct_xdp_md field")

        return value

    def _parsed_members(self, vmlinux_struct_name):
        """
        Return the dict of fields the vmlinux parser actually produced for a struct.

        This is the single source of truth for "does the compiler know about this
        field", as opposed to `hasattr(python_type, ...)` which merely reports what
        ctypes exposes on the class (including members the parser never registered).
        """
        if not self.is_vmlinux_struct(vmlinux_struct_name):
            raise ValueError(f"{vmlinux_struct_name} is not a vmlinux struct")
        return self.vmlinux_symtab[vmlinux_struct_name].members

    def _unsupported_field_error(self, vmlinux_struct_name, field_name):
        """Build an actionable error for a field lookup that failed."""
        python_type = self.vmlinux_symtab[vmlinux_struct_name].python_type
        if hasattr(python_type, field_name):
            return ValueError(
                f"Field {field_name} of vmlinux struct {vmlinux_struct_name} exists in "
                "vmlinux.py but was not registered by the vmlinux parser, so it cannot "
                "be accessed yet (unsupported field kind)"
            )
        return ValueError(
            f"Field {field_name} not found in vmlinux struct {vmlinux_struct_name}"
        )

    def has_field(self, struct_name, field_name):
        """Check if a vmlinux struct has a specific field the parser understands"""
        if self.is_vmlinux_struct(struct_name):
            return field_name in self.vmlinux_symtab[struct_name].members
        return False

    def get_field_type(self, vmlinux_struct_name, field_name):
        """Get the type of a field in a vmlinux struct"""
        members = self._parsed_members(vmlinux_struct_name)
        if field_name in members:
            return members[field_name]
        raise self._unsupported_field_error(vmlinux_struct_name, field_name)

    def get_field_index(self, vmlinux_struct_name, field_name):
        """
        Get the declaration index of a field in a vmlinux struct.

        The index is derived from the ctypes `_fields_` list, i.e. from the C
        declaration order, rather than from the insertion order of the parsed
        members dict.
        """
        members = self._parsed_members(vmlinux_struct_name)
        if field_name not in members:
            raise self._unsupported_field_error(vmlinux_struct_name, field_name)

        python_type = self.vmlinux_symtab[vmlinux_struct_name].python_type
        declared_fields = getattr(python_type, "_fields_", None)
        if declared_fields is not None:
            for index, declared in enumerate(declared_fields):
                if declared[0] == field_name:
                    return index
        # No `_fields_` (or the field is not declared at the top level, e.g. it was
        # flattened out of an anonymous member): fall back to the parsed ordering.
        return list(members.keys()).index(field_name)
