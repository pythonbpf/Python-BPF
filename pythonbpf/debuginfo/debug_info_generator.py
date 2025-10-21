"""
Debug information generation module for Python-BPF
Provides utilities for generating DWARF/BTF debug information
"""

from . import dwarf_constants as dc
from typing import Any, List


class DebugInfoGenerator:
    def __init__(self, module):
        self.module = module
        self._type_cache = {}  # Cache for common debug types

    def generate_file_metadata(self, filename, dirname):
        self.module._file_metadata = self.module.add_debug_info(
            "DIFile",
            {  # type: ignore
                "filename": filename,
                "directory": dirname,
            },
        )

    def generate_debug_cu(
        self, language, producer: str, is_optimized: bool, is_distinct: bool
    ):
        self.module._debug_compile_unit = self.module.add_debug_info(
            "DICompileUnit",
            {  # type: ignore
                "language": language,
                "file": self.module._file_metadata,  # type: ignore
                "producer": producer,
                "isOptimized": is_optimized,
                "runtimeVersion": 0,
                "emissionKind": 1,
                "splitDebugInlining": False,
                "nameTableKind": 0,
            },
            is_distinct=is_distinct,
        )
        self.module.add_named_metadata("llvm.dbg.cu", self.module._debug_compile_unit)  # type: ignore

    def get_basic_type(self, name: str, size: int, encoding: int) -> Any:
        """Get or create a basic type with caching"""
        key = (name, size, encoding)
        if key not in self._type_cache:
            self._type_cache[key] = self.module.add_debug_info(
                "DIBasicType", {"name": name, "size": size, "encoding": encoding}
            )
        return self._type_cache[key]

    def get_int32_type(self) -> Any:
        """Get debug info for signed 32-bit integer"""
        return self.get_basic_type("int", 32, dc.DW_ATE_signed)

    def get_uint32_type(self) -> Any:
        """Get debug info for unsigned 32-bit integer"""
        return self.get_basic_type("unsigned int", 32, dc.DW_ATE_unsigned)

    def get_uint64_type(self) -> Any:
        """Get debug info for unsigned 64-bit integer"""
        return self.get_basic_type("unsigned long long", 64, dc.DW_ATE_unsigned)

    def create_pointer_type(self, base_type: Any, size: int = 64) -> Any:
        """Create a pointer type to the given base type"""
        return self.module.add_debug_info(
            "DIDerivedType",
            {"tag": dc.DW_TAG_pointer_type, "baseType": base_type, "size": size},
        )

    def create_array_type(self, base_type: Any, count: int) -> Any:
        """Create an array type of the given base type with specified count"""
        subrange = self.module.add_debug_info("DISubrange", {"count": count})
        return self.module.add_debug_info(
            "DICompositeType",
            {
                "tag": dc.DW_TAG_array_type,
                "baseType": base_type,
                "size": self._compute_array_size(base_type, count),
                "elements": [subrange],
            },
        )

    def create_array_type_vmlinux(self, type_info: Any, count: int) -> Any:
        """Create an array type of the given base type with specified count"""
        base_type, type_sizing = type_info
        subrange = self.module.add_debug_info("DISubrange", {"count": count})
        return self.module.add_debug_info(
            "DICompositeType",
            {
                "tag": dc.DW_TAG_array_type,
                "baseType": base_type,
                "size": type_sizing,
                "elements": [subrange],
            },
        )

    @staticmethod
    def _compute_array_size(base_type: Any, count: int) -> int:
        # Extract size from base_type if possible
        # For simplicity, assuming base_type has a size attribute
        return getattr(base_type, "size", 32) * count

    def create_struct_member(self, name: str, base_type: Any, offset: int) -> Any:
        """Create a struct member with the given name, type, and offset"""
        return self.module.add_debug_info(
            "DIDerivedType",
            {
                "tag": dc.DW_TAG_member,
                "name": name,
                "file": self.module._file_metadata,
                "baseType": base_type,
                "size": getattr(base_type, "size", 64),
                "offset": offset,
            },
        )

    def create_struct_member_vmlinux(
        self, name: str, base_type_with_size: Any, offset: int
    ) -> Any:
        """Create a struct member with the given name, type, and offset"""
        base_type, type_size = base_type_with_size
        return self.module.add_debug_info(
            "DIDerivedType",
            {
                "tag": dc.DW_TAG_member,
                "name": name,
                "file": self.module._file_metadata,
                "baseType": base_type,
                "size": type_size,
                "offset": offset,
            },
        )

    def create_struct_type(
        self, members: List[Any], size: int, is_distinct: bool
    ) -> Any:
        """Create a struct type with the given members and size"""
        return self.module.add_debug_info(
            "DICompositeType",
            {
                "tag": dc.DW_TAG_structure_type,
                "file": self.module._file_metadata,
                "size": size,
                "elements": members,
            },
            is_distinct=is_distinct,
        )

    def create_struct_type_with_name(
        self, name: str, members: List[Any], size: int, is_distinct: bool
    ) -> Any:
        """Create a struct type with the given members and size"""
        return self.module.add_debug_info(
            "DICompositeType",
            {
                "name": name,
                "tag": dc.DW_TAG_structure_type,
                "file": self.module._file_metadata,
                "size": size,
                "elements": members,
            },
            is_distinct=is_distinct,
        )

    def create_global_var_debug_info(
        self, name: str, var_type: Any, is_local: bool = False
    ) -> Any:
        """Create debug info for a global variable"""
        global_var = self.module.add_debug_info(
            "DIGlobalVariable",
            {
                "name": name,
                "scope": self.module._debug_compile_unit,
                "file": self.module._file_metadata,
                "type": var_type,
                "isLocal": is_local,
                "isDefinition": True,
            },
            is_distinct=True,
        )

        return self.module.add_debug_info(
            "DIGlobalVariableExpression",
            {"var": global_var, "expr": self.module.add_debug_info("DIExpression", {})},
        )
