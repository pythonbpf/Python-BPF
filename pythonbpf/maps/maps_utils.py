from collections.abc import Callable
from dataclasses import dataclass
from llvmlite import ir
from typing import Any
from .map_types import BPFMapType


@dataclass
class MapSymbol:
    """Class representing a symbol on the map"""

    type: BPFMapType
    sym: ir.GlobalVariable
    params: dict[str, Any] | None = None


class MapProcessorRegistry:
    """Registry for map processor functions"""

    _processors: dict[str, Callable[..., Any]] = {}

    @classmethod
    def register(cls, map_type_name):
        """Decorator to register a processor function for a map type"""

        def decorator(func):
            cls._processors[map_type_name] = func
            return func

        return decorator

    @classmethod
    def get_processor(cls, map_type_name):
        """Get the processor function for a map type"""
        return cls._processors.get(map_type_name)

    @classmethod
    def known_types(cls):
        """Names of every registered map type, for error messages"""
        return list(cls._processors)
