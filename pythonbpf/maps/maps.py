"""
BPF map type definitions for Python type hints.

This module provides Python classes that represent BPF map types.
These are used for type checking and map definition; the actual BPF maps
are generated as LLVM IR during compilation.
"""

# This file provides type  and function hints only and does not actually give any functionality.
class HashMap:
    """
    A BPF hash map for storing key-value pairs.
    
    This is a type hint class used during compilation. The actual BPF map
    implementation is generated as LLVM IR.
    """
    
    def __init__(self, key, value, max_entries):
        """
        Initialize a HashMap definition.
        
        Args:
            key: The ctypes type for keys (e.g., c_int64)
            value: The ctypes type for values (e.g., c_int64)
            max_entries: Maximum number of entries the map can hold
        """
        self.key = key
        self.value = value
        self.max_entries = max_entries
        self.entries = {}

    def lookup(self, key):
        """
        Look up a value by key in the map.
        
        Args:
            key: The key to look up
        
        Returns:
            The value if found, None otherwise
        """
        if key in self.entries:
            return self.entries[key]
        else:
            return None

    def delete(self, key):
        """
        Delete an entry from the map by key.
        
        Args:
            key: The key to delete
        
        Raises:
            KeyError: If the key is not found in the map
        """
        if key in self.entries:
            del self.entries[key]
        else:
            raise KeyError(f"Key {key} not found in map")

    # TODO: define the flags that can be added
    def update(self, key, value, flags=None):
        """
        Update or insert a key-value pair in the map.
        
        Args:
            key: The key to update
            value: The new value
            flags: Optional flags for update behavior
        
        Raises:
            KeyError: If the key is not found in the map
        """
        if key in self.entries:
            self.entries[key] = value
        else:
            raise KeyError(f"Key {key} not found in map")


class PerfEventArray:
    """
    A BPF perf event array for sending data to userspace.
    
    This is a type hint class used during compilation.
    """
    
    def __init__(self, key_size, value_size):
        """
        Initialize a PerfEventArray definition.
        
        Args:
            key_size: The size/type for keys
            value_size: The size/type for values
        """
        self.key_type = key_size
        self.value_type = value_size
        self.entries = {}

    def output(self, data):
        """
        Output data to the perf event array.
        
        Args:
            data: The data to output
        """
        pass  # Placeholder for output method


class RingBuf:
    """
    A BPF ring buffer for efficient data transfer to userspace.
    
    This is a type hint class used during compilation.
    """
    
    def __init__(self, max_entries):
        """
        Initialize a RingBuf definition.
        
        Args:
            max_entries: Maximum number of entries the ring buffer can hold
        """
        self.max_entries = max_entries

    def reserve(self, size: int, flags=0):
        """
        Reserve space in the ring buffer.
        
        Args:
            size: Size in bytes to reserve
            flags: Optional reservation flags
        
        Returns:
            0 as a placeholder (actual implementation is in BPF runtime)
        
        Raises:
            ValueError: If size exceeds max_entries
        """
        if size > self.max_entries:
            raise ValueError("size cannot be greater than set maximum entries")
        return 0

    def submit(self, data, flags=0):
        """
        Submit data to the ring buffer.
        
        Args:
            data: The data to submit
            flags: Optional submission flags
        """
        pass

    # add discard, output and also give names to flags and stuff
