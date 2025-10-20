from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import ctypes


# TODO: FIX THE FUCKING TYPE NAME CONVENTION.
@dataclass
class Field:
    """Represents a field in a dependency node with its type and readiness state."""

    name: str
    type: type
    ctype_complex_type: Optional[Any]
    containing_type: Optional[Any]
    type_size: Optional[int]
    bitfield_size: Optional[int]
    offset: int
    value: Any = None
    ready: bool = False

    def __hash__(self):
        """
        Create a hash based on the immutable attributes that define this field's identity.
        This allows Field objects to be used as dictionary keys.
        """
        # Use a tuple of the fields that uniquely identify this field
        identity = (
            self.name,
            id(self.type),  # Use id for non-hashable types
            id(self.ctype_complex_type) if self.ctype_complex_type else None,
            id(self.containing_type) if self.containing_type else None,
            self.type_size,
            self.bitfield_size,
            self.offset,
            self.value if self.value else None,
        )
        return hash(identity)

    def __eq__(self, other):
        """
        Define equality consistent with the hash function.
        Two fields are equal if they have they are the same
        """
        return self is other

    def set_ready(self, is_ready: bool = True) -> None:
        """Set the readiness state of this field."""
        self.ready = is_ready

    def set_value(self, value: Any, mark_ready: bool = False) -> None:
        """Set the value of this field and optionally mark it as ready."""
        self.value = value
        if mark_ready:
            self.ready = True

    def set_type(self, given_type, mark_ready: bool = False) -> None:
        """Set value of the type field and mark as ready"""
        self.type = given_type
        if mark_ready:
            self.ready = True

    def set_containing_type(
        self, containing_type: Optional[Any], mark_ready: bool = False
    ) -> None:
        """Set the containing_type of this field and optionally mark it as ready."""
        self.containing_type = containing_type
        if mark_ready:
            self.ready = True

    def set_type_size(self, type_size: Any, mark_ready: bool = False) -> None:
        """Set the type_size of this field and optionally mark it as ready."""
        self.type_size = type_size
        if mark_ready:
            self.ready = True

    def set_ctype_complex_type(
        self, ctype_complex_type: Any, mark_ready: bool = False
    ) -> None:
        """Set the ctype_complex_type of this field and optionally mark it as ready."""
        self.ctype_complex_type = ctype_complex_type
        if mark_ready:
            self.ready = True

    def set_bitfield_size(self, bitfield_size: Any, mark_ready: bool = False) -> None:
        """Set the bitfield_size of this field and optionally mark it as ready."""
        self.bitfield_size = bitfield_size
        if mark_ready:
            self.ready = True

    def set_offset(self, offset: int) -> None:
        """Set the offset of this field"""
        self.offset = offset


@dataclass
class DependencyNode:
    """
    A node with typed fields and readiness tracking.

    Example usage:
        # Create a dependency node for a Person
        somestruct = DependencyNode(name="struct_1")

        # Add fields with their types
        somestruct.add_field("field_1", str)
        somestruct.add_field("field_2", int)
        somestruct.add_field("field_3", str)

        # Check if the node is ready (should be False initially)
        print(f"Is node ready? {somestruct.is_ready}")  # False

        # Set some field values
        somestruct.set_field_value("field_1", "someproperty")
        somestruct.set_field_value("field_2", 30)

        # Check if the node is ready (still False because email is not ready)
        print(f"Is node ready? {somestruct.is_ready}")  # False

        # Set the last field and make the node ready
        somestruct.set_field_value("field_3", "anotherproperty")

        # Now the node should be ready
        print(f"Is node ready? {somestruct.is_ready}")  # True

        # You can also mark a field as not ready
        somestruct.set_field_ready("field_3", False)

        # Now the node is not ready again
        print(f"Is node ready? {somestruct.is_ready}")  # False

        # Get all field values
        print(somestruct.get_field_values())  # {'field_1': 'someproperty', 'field_2': 30, 'field_3': 'anotherproperty'}

        # Get only ready fields
        ready_fields = somestruct.get_ready_fields()
        print(f"Ready fields: {[field.name for field in ready_fields.values()]}")  # ['field_1', 'field_2']
    """

    name: str
    depends_on: Optional[list[str]] = None
    fields: Dict[str, Field] = field(default_factory=dict)
    _ready_cache: Optional[bool] = field(default=None, repr=False)
    current_offset: int = 0
    ctype_struct: Optional[Any] = field(default=None, repr=False)

    def add_field(
        self,
        name: str,
        field_type: type,
        initial_value: Any = None,
        containing_type: Optional[Any] = None,
        type_size: Optional[int] = None,
        ctype_complex_type: Optional[int] = None,
        bitfield_size: Optional[int] = None,
        ready: bool = False,
        offset: int = 0,
    ) -> None:
        """Add a field to the node with an optional initial value and readiness state."""
        if self.depends_on is None:
            self.depends_on = []
        self.fields[name] = Field(
            name=name,
            type=field_type,
            value=initial_value,
            ready=ready,
            containing_type=containing_type,
            type_size=type_size,
            ctype_complex_type=ctype_complex_type,
            bitfield_size=bitfield_size,
            offset=offset,
        )
        # Invalidate readiness cache
        self._ready_cache = None

    def set_ctype_struct(self, ctype_struct: Any) -> None:
        """Set the ctypes structure for automatic offset calculation."""
        self.ctype_struct = ctype_struct

    def __sizeof__(self):
        # If we have a ctype_struct, use its size
        if self.ctype_struct is not None:
            return ctypes.sizeof(self.ctype_struct)
        return self.current_offset

    def get_field(self, name: str) -> Field:
        """Get a field by name."""
        return self.fields[name]

    def set_field_value(self, name: str, value: Any, mark_ready: bool = False) -> None:
        """Set a field's value and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_value(value, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_type(self, name: str, type: Any, mark_ready: bool = False) -> None:
        """Set a field's type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_type(type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_containing_type(
        self, name: str, containing_type: Any, mark_ready: bool = False
    ) -> None:
        """Set a field's containing_type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_containing_type(containing_type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_type_size(
        self, name: str, type_size: Any, mark_ready: bool = False
    ) -> None:
        """Set a field's type_size and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_type_size(type_size, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_ctype_complex_type(
        self, name: str, ctype_complex_type: Any, mark_ready: bool = False
    ) -> None:
        """Set a field's ctype_complex_type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_ctype_complex_type(ctype_complex_type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_bitfield_size(
        self, name: str, bitfield_size: Any, mark_ready: bool = False
    ) -> None:
        """Set a field's bitfield_size and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_bitfield_size(bitfield_size, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_ready(
        self,
        name: str,
        is_ready: bool = False,
        size_of_containing_type: Optional[int] = None,
    ) -> None:
        """Mark a field as ready or not ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_ready(is_ready)

        # Use ctypes built-in offset if available
        if self.ctype_struct is not None:
            try:
                self.fields[name].set_offset(getattr(self.ctype_struct, name).offset)
            except AttributeError:
                # Fallback to manual calculation if field not found in ctype_struct
                self.fields[name].set_offset(self.current_offset)
                self.current_offset += self._calculate_size(
                    name, size_of_containing_type
                )
        else:
            # Manual offset calculation when no ctype_struct is available
            self.fields[name].set_offset(self.current_offset)
            self.current_offset += self._calculate_size(name, size_of_containing_type)

        # Invalidate readiness cache
        self._ready_cache = None

    def _calculate_size(
        self, name: str, size_of_containing_type: Optional[int] = None
    ) -> int:
        processing_field = self.fields[name]
        # size_of_field will be in bytes
        if processing_field.type.__module__ == ctypes.__name__:
            size_of_field = ctypes.sizeof(processing_field.type)
            return size_of_field
        elif processing_field.type.__module__ == "vmlinux":
            if processing_field.ctype_complex_type is not None:
                if issubclass(processing_field.ctype_complex_type, ctypes.Array):
                    if processing_field.containing_type.__module__ == ctypes.__name__:
                        if (
                            processing_field.containing_type is not None
                            and processing_field.type_size is not None
                        ):
                            size_of_field = (
                                ctypes.sizeof(processing_field.containing_type)
                                * processing_field.type_size
                            )
                        else:
                            raise RuntimeError(
                                f"{processing_field} has no containing_type or type_size"
                            )
                        return size_of_field
                    elif processing_field.containing_type.__module__ == "vmlinux":
                        if (
                            size_of_containing_type is not None
                            and processing_field.type_size is not None
                        ):
                            size_of_field = (
                                size_of_containing_type * processing_field.type_size
                            )
                        else:
                            raise RuntimeError(
                                f"{processing_field} has no containing_type or type_size"
                            )
                        return size_of_field
                elif issubclass(processing_field.ctype_complex_type, ctypes._Pointer):
                    return ctypes.sizeof(ctypes.c_void_p)
                else:
                    raise NotImplementedError(
                        "This subclass of ctype not supported yet"
                    )
            elif processing_field.type_size is not None:
                # Handle vmlinux types with type_size but no ctype_complex_type
                # This means it's a direct vmlinux struct field (not array/pointer wrapped)
                # The type_size should already contain the full size of the struct
                # But if there's a containing_type from vmlinux, we need that size
                if processing_field.containing_type is not None:
                    if processing_field.containing_type.__module__ == "vmlinux":
                        # For vmlinux containing types, we need the pre-calculated size
                        if size_of_containing_type is not None:
                            return size_of_containing_type * processing_field.type_size
                        else:
                            raise RuntimeError(
                                f"Field {name}: vmlinux containing_type requires size_of_containing_type"
                            )
                    else:
                        raise ModuleNotFoundError(
                            f"Containing type module {processing_field.containing_type.__module__} not supported"
                        )
                else:
                    raise RuntimeError("Wrong type found with no containing type")
            else:
                # No ctype_complex_type and no type_size, must rely on size_of_containing_type
                if size_of_containing_type is None:
                    raise RuntimeError(
                        f"Size of containing type {size_of_containing_type} is None"
                    )
                return size_of_containing_type

        else:
            raise ModuleNotFoundError("Module is not supported for the operation")
        raise RuntimeError("control should not reach here")

    @property
    def is_ready(self) -> bool:
        """Check if the node is ready (all fields are ready)."""
        # Use cached value if available
        if self._ready_cache is not None:
            return self._ready_cache

        # Calculate readiness only when needed
        if not self.fields:
            self._ready_cache = True
            return True

        self._ready_cache = all(elem.ready for elem in self.fields.values())
        return self._ready_cache

    def get_field_values(self) -> Dict[str, Any]:
        """Get a dictionary of field names to their values."""
        return {name: elem.value for name, elem in self.fields.items()}

    def get_ready_fields(self) -> Dict[str, Field]:
        """Get all fields that are marked as ready."""
        return {name: elem for name, elem in self.fields.items() if elem.ready}

    def get_not_ready_fields(self) -> Dict[str, Field]:
        """Get all fields that are marked as not ready."""
        return {name: elem for name, elem in self.fields.items() if not elem.ready}

    def add_dependent(self, dep_type):
        if dep_type in self.depends_on:
            return
        else:
            self.depends_on.append(dep_type)
