from typing import Optional, Dict, List, Iterator
from .dependency_node import DependencyNode


class DependencyHandler:
    """
    Manages a collection of DependencyNode objects with no duplicates.

    Ensures that no two nodes with the same name can be added and provides
    methods to check readiness and retrieve specific nodes.

    Example usage:
        # Create a handler
        handler = DependencyHandler()

        # Create some dependency nodes
        node1 = DependencyNode(name="node1")
        node1.add_field("field1", str)
        node1.set_field_value("field1", "value1")

        node2 = DependencyNode(name="node2")
        node2.add_field("field1", int)

        # Add nodes to the handler
        handler.add_node(node1)
        handler.add_node(node2)

        # Check if a specific node exists
        print(handler.has_node("node1"))  # True

        # Get a reference to a node and modify it
        node = handler.get_node("node2")
        node.set_field_value("field1", 42)

        # Check if all nodes are ready
        print(handler.is_ready)  # False (node2 is ready, but node1 isn't)
    """

    def __init__(self):
        # Using a dictionary with node names as keys ensures name uniqueness
        # and provides efficient lookups
        self._nodes: Dict[str, DependencyNode] = {}

    def add_node(self, node: DependencyNode) -> bool:
        """
        Add a dependency node to the handler.

        Args:
            node: The DependencyNode to add

        Returns:
            bool: True if the node was added, False if a node with the same name already exists

        Raises:
            TypeError: If the provided object is not a DependencyNode
        """
        if not isinstance(node, DependencyNode):
            raise TypeError(f"Expected DependencyNode, got {type(node).__name__}")

        # Check if a node with this name already exists
        if node.name in self._nodes:
            return False

        self._nodes[node.name] = node
        return True

    @property
    def is_ready(self) -> bool:
        """
        Check if all nodes are ready.

        Returns:
            bool: True if all nodes are ready (or if there are no nodes), False otherwise
        """
        if not self._nodes:
            return True

        return all(node.is_ready for node in self._nodes.values())

    def has_node(self, name: str) -> bool:
        """
        Check if a node with the given name exists.

        Args:
            name: The name to check

        Returns:
            bool: True if a node with the given name exists, False otherwise
        """
        return name in self._nodes

    def get_node(self, name: str) -> Optional[DependencyNode]:
        """
        Get a node by name for manipulation.

        Args:
            name: The name of the node to retrieve

        Returns:
            Optional[DependencyNode]: The node with the given name, or None if not found
        """
        return self._nodes.get(name)

    def remove_node(self, node_or_name) -> bool:
        """
        Remove a node by name or reference.

        Args:
            node_or_name: The node to remove or its name

        Returns:
            bool: True if the node was removed, False if not found
        """
        if isinstance(node_or_name, DependencyNode):
            name = node_or_name.name
        else:
            name = node_or_name

        if name in self._nodes:
            del self._nodes[name]
            return True
        return False

    def get_all_nodes(self) -> List[DependencyNode]:
        """
        Get all nodes stored in the handler.

        Returns:
            List[DependencyNode]: List of all nodes
        """
        return list(self._nodes.values())

    def __iter__(self) -> Iterator[DependencyNode]:
        """
        Iterate over all nodes.

        Returns:
            Iterator[DependencyNode]: Iterator over all nodes
        """
        return iter(self._nodes.values())

    def __len__(self) -> int:
        """
        Get the number of nodes in the handler.

        Returns:
            int: The number of nodes
        """
        return len(self._nodes)

    def __getitem__(self, name: str) -> DependencyNode:
        """
        Get a node by name using dictionary-style access.

        Args:
            name: The name of the node to retrieve

        Returns:
            DependencyNode: The node with the given name

        Raises:
            KeyError: If no node with the given name exists

        Example:
            node = handler["some-dep_node_name"]
        """
        if name not in self._nodes:
            raise KeyError(f"No node with name '{name}' found")
        return self._nodes[name]

    @property
    def nodes(self):
        return self._nodes
