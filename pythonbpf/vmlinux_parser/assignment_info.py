from enum import Enum, auto
from typing import Any, Dict, List, Optional, TypedDict
from dataclasses import dataclass
import llvmlite.ir as ir

from pythonbpf.vmlinux_parser.dependency_node import Field


@dataclass
class AssignmentType(Enum):
    CONSTANT = auto()
    STRUCT = auto()
    ARRAY = auto()  # probably won't be used
    FUNCTION_POINTER = auto()
    POINTER = auto()  # again, probably won't be used


@dataclass
class FunctionSignature(TypedDict):
    return_type: str
    param_types: List[str]
    varargs: bool


# Thew name of the assignment will be in the dict that uses this class
@dataclass
class AssignmentInfo(TypedDict):
    value_type: AssignmentType
    python_type: type
    value: Optional[Any]
    pointer_level: Optional[int]
    signature: Optional[FunctionSignature]  # For function pointers
    # The key of the dict is the name of the field.
    #   Value is a tuple that contains the global variable representing that field
    #   along with all the information about that field as a Field type.
    members: Optional[Dict[str, tuple[ir.GlobalVariable, Field]]]  # For structs.
