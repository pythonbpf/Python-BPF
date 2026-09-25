# This file provides type  and function hints only and does not actually give any functionality.
class HashMap:
    def __init__(self, key, value, max_entries):
        self.key = key
        self.value = value
        self.max_entries = max_entries
        self.entries = {}

    def lookup(self, key):
        if key in self.entries:
            return self.entries[key]
        else:
            return None

    def delete(self, key):
        if key in self.entries:
            del self.entries[key]
        else:
            raise KeyError(f"Key {key} not found in map")

    # TODO: define the flags that can be added
    def update(self, key, value, flags=None):
        if key in self.entries:
            self.entries[key] = value
        else:
            raise KeyError(f"Key {key} not found in map")


class ArrayMap:
    def __init__(self, key, value, max_entries):
        self.key = key
        self.value = value
        self.max_entries = max_entries
        self.entries = {}

    def lookup(self, key):
        return self.entries.get(key)

    def update(self, key, value, flags=None):
        self.entries[key] = value

    def delete(self, key):
        if key in self.entries:
            del self.entries[key]
        else:
            raise KeyError(f"Key {key} not found in map")


class PerfEventArray:
    def __init__(self, key_size, value_size):
        self.key_type = key_size
        self.value_type = value_size
        self.entries = {}

    def output(self, data):
        pass  # Placeholder for output method


class RingBuffer:
    def __init__(self, max_entries):
        self.max_entries = max_entries

    def output(self, data, flags=0):
        pass

    def reserve(self, size: int):
        if size > self.max_entries:
            raise ValueError("size cannot be greater than set maximum entries")
        return 0

    def submit(self, data, flags=0):
        pass

    def discard(self, data, flags=0):
        pass

    # add discard, output and also give names to flags and stuff
