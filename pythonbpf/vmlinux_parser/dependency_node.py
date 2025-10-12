from dataclasses import dataclass, field
from typing import Dict, Any, Optional


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
    value: Any = None
    ready: bool = False

    def set_ready(self, is_ready: bool = True) -> None:
        """Set the readiness state of this field."""
        self.ready = is_ready

    def set_value(self, value: Any, mark_ready: bool = True) -> None:
        """Set the value of this field and optionally mark it as ready."""
        self.value = value
        if mark_ready:
            self.ready = True

    def set_type(self, given_type, mark_ready: bool = True) -> None:
        """Set value of the type field and mark as ready"""
        self.type = given_type
        if mark_ready:
            self.ready = True

    def set_containing_type(
        self, containing_type: Optional[Any], mark_ready: bool = True
    ) -> None:
        """Set the containing_type of this field and optionally mark it as ready."""
        self.containing_type = containing_type
        if mark_ready:
            self.ready = True

    def set_type_size(self, type_size: Any, mark_ready: bool = True) -> None:
        """Set the type_size of this field and optionally mark it as ready."""
        self.type_size = type_size
        if mark_ready:
            self.ready = True

    def set_ctype_complex_type(
        self, ctype_complex_type: Any, mark_ready: bool = True
    ) -> None:
        """Set the ctype_complex_type of this field and optionally mark it as ready."""
        self.ctype_complex_type = ctype_complex_type
        if mark_ready:
            self.ready = True

    def set_bitfield_size(self, bitfield_size: Any, mark_ready: bool = True) -> None:
        """Set the bitfield_size of this field and optionally mark it as ready."""
        self.bitfield_size = bitfield_size
        if mark_ready:
            self.ready = True


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
    fields: Dict[str, Field] = field(default_factory=dict)
    _ready_cache: Optional[bool] = field(default=None, repr=False)

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
    ) -> None:
        """Add a field to the node with an optional initial value and readiness state."""
        self.fields[name] = Field(
            name=name,
            type=field_type,
            value=initial_value,
            ready=ready,
            containing_type=containing_type,
            type_size=type_size,
            ctype_complex_type=ctype_complex_type,
            bitfield_size=bitfield_size,
        )
        # Invalidate readiness cache
        self._ready_cache = None

    def get_field(self, name: str) -> Field:
        """Get a field by name."""
        return self.fields[name]

    def set_field_value(self, name: str, value: Any, mark_ready: bool = True) -> None:
        """Set a field's value and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_value(value, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_type(self, name: str, type: Any, mark_ready: bool = True) -> None:
        """Set a field's type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_type(type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_containing_type(
        self, name: str, containing_type: Any, mark_ready: bool = True
    ) -> None:
        """Set a field's containing_type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_containing_type(containing_type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_type_size(
        self, name: str, type_size: Any, mark_ready: bool = True
    ) -> None:
        """Set a field's type_size and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_type_size(type_size, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_ctype_complex_type(
        self, name: str, ctype_complex_type: Any, mark_ready: bool = True
    ) -> None:
        """Set a field's ctype_complex_type and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_ctype_complex_type(ctype_complex_type, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_bitfield_size(
        self, name: str, bitfield_size: Any, mark_ready: bool = True
    ) -> None:
        """Set a field's bitfield_size and optionally mark it as ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_bitfield_size(bitfield_size, mark_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    def set_field_ready(self, name: str, is_ready: bool = True) -> None:
        """Mark a field as ready or not ready."""
        if name not in self.fields:
            raise KeyError(f"Field '{name}' does not exist in node '{self.name}'")

        self.fields[name].set_ready(is_ready)
        # Invalidate readiness cache
        self._ready_cache = None

    @property
    def is_ready(self) -> bool:
        """Check if the node is ready (all fields are ready)."""
        # Use cached value if available
        if self._ready_cache is not None:
            return self._ready_cache

        # Calculate readiness only when needed
        if not self.fields:
            self._ready_cache = False
            return False

        self._ready_cache = all(elem.ready for elem in self.fields.values())
        return self._ready_cache

    def get_field_values(self) -> Dict[str, Any]:
        """Get a dictionary of field names to their values."""
        return {name: elem.value for name, elem in self.fields.items()}

    def get_ready_fields(self) -> Dict[str, Field]:
        """Get all fields that are marked as ready."""
        return {name: elem for name, elem in self.fields.items() if elem.ready}
