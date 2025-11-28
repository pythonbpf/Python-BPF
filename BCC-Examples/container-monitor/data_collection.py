"""Data collection and management for container monitoring."""

import os
import time
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from collections import deque, defaultdict


@dataclass
class CgroupInfo:
    """Information about a cgroup."""

    id: int
    name: str
    path: str


@dataclass
class ContainerStats:
    """Statistics for a container/cgroup."""

    cgroup_id: int
    cgroup_name: str

    # File I/O
    read_ops: int = 0
    read_bytes: int = 0
    write_ops: int = 0
    write_bytes: int = 0

    # Network I/O
    rx_packets: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    tx_bytes: int = 0

    # Syscalls
    syscall_count: int = 0

    # Timestamp
    timestamp: float = 0.0


class ContainerDataCollector:
    """Collects and manages container monitoring data from BPF."""

    def __init__(
        self, read_map, write_map, net_stats_map, syscall_map, history_size: int = 100
    ):
        self.read_map = read_map
        self.write_map = write_map
        self.net_stats_map = net_stats_map
        self.syscall_map = syscall_map

        # Caching
        self._cgroup_cache: Dict[int, CgroupInfo] = {}
        self._cgroup_cache_time = 0
        self._cache_ttl = 5.0
        0  # Refresh cache every 5 seconds

        # Historical data for graphing
        self._history_size = history_size
        self._history: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=history_size)
        )

    def get_all_cgroups(self) -> List[CgroupInfo]:
        """Get all cgroups with caching."""
        current_time = time.time()

        # Use cached data if still valid
        if current_time - self._cgroup_cache_time < self._cache_ttl:
            return list(self._cgroup_cache.values())

        # Refresh cache
        self._refresh_cgroup_cache()
        return list(self._cgroup_cache.values())

    def _refresh_cgroup_cache(self):
        """Refresh the cgroup cache from /proc."""
        cgroup_map: Dict[int, Set[str]] = defaultdict(set)

        # Scan /proc to find all cgroups
        for proc_dir in Path("/proc").glob("[0-9]*"):
            try:
                cgroup_file = proc_dir / "cgroup"
                if not cgroup_file.exists():
                    continue

                with open(cgroup_file) as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            cgroup_path = parts[2]
                            cgroup_mount = f"/sys/fs/cgroup{cgroup_path}"

                            if os.path.exists(cgroup_mount):
                                stat_info = os.stat(cgroup_mount)
                                cgroup_id = stat_info.st_ino
                                cgroup_map[cgroup_id].add(cgroup_path)

            except (PermissionError, FileNotFoundError, OSError):
                continue

        # Update cache with best names
        new_cache = {}
        for cgroup_id, paths in cgroup_map.items():
            # Pick the most descriptive path
            best_path = self._get_best_cgroup_path(paths)
            name = self._get_cgroup_name(best_path)

            new_cache[cgroup_id] = CgroupInfo(id=cgroup_id, name=name, path=best_path)

        self._cgroup_cache = new_cache
        self._cgroup_cache_time = time.time()

    def _get_best_cgroup_path(self, paths: Set[str]) -> str:
        """Select the most descriptive cgroup path."""
        path_list = list(paths)

        # Prefer paths with more components (more specific)
        # Prefer paths containing docker, podman, etc.
        for keyword in ["docker", "podman", "kubernetes", "k8s", "systemd"]:
            for path in path_list:
                if keyword in path.lower():
                    return path

        # Return longest path (most specific)
        return max(path_list, key=lambda p: (len(p.split("/")), len(p)))

    def _get_cgroup_name(self, path: str) -> str:
        """Extract a friendly name from cgroup path."""
        if not path or path == "/":
            return "root"

        # Remove leading/trailing slashes
        path = path.strip("/")

        # Try to extract container ID or service name
        parts = path.split("/")

        # For Docker: /docker/<container_id>
        if "docker" in path.lower():
            for i, part in enumerate(parts):
                if part.lower() == "docker" and i + 1 < len(parts):
                    container_id = parts[i + 1][:12]  # Short ID
                    return f"docker:{container_id}"

        # For systemd services
        if "system.slice" in path:
            for part in parts:
                if part.endswith(".service"):
                    return part.replace(".service", "")

        # For user slices
        if "user.slice" in path:
            return f"user:{parts[-1]}" if parts else "user"

        # Default: use last component
        return parts[-1] if parts else path

    def get_stats_for_cgroup(self, cgroup_id: int) -> ContainerStats:
        """Get current statistics for a specific cgroup."""
        cgroup_info = self._cgroup_cache.get(cgroup_id)
        cgroup_name = cgroup_info.name if cgroup_info else f"cgroup-{cgroup_id}"

        stats = ContainerStats(
            cgroup_id=cgroup_id, cgroup_name=cgroup_name, timestamp=time.time()
        )

        # Get file I/O stats
        read_stat = self.read_map.lookup(cgroup_id)
        if read_stat:
            stats.read_ops = int(read_stat.ops)
            stats.read_bytes = int(read_stat.bytes)

        write_stat = self.write_map.lookup(cgroup_id)
        if write_stat:
            stats.write_ops = int(write_stat.ops)
            stats.write_bytes = int(write_stat.bytes)

        # Get network stats
        net_stat = self.net_stats_map.lookup(cgroup_id)
        if net_stat:
            stats.rx_packets = int(net_stat.rx_packets)
            stats.rx_bytes = int(net_stat.rx_bytes)
            stats.tx_packets = int(net_stat.tx_packets)
            stats.tx_bytes = int(net_stat.tx_bytes)

        # Get syscall count
        syscall_cnt = self.syscall_map.lookup(cgroup_id)
        if syscall_cnt is not None:
            stats.syscall_count = int(syscall_cnt)

        # Add to history
        self._history[cgroup_id].append(stats)

        return stats

    def get_history(self, cgroup_id: int) -> List[ContainerStats]:
        """Get historical statistics for graphing."""
        return list(self._history[cgroup_id])

    def get_cgroup_info(self, cgroup_id: int) -> Optional[CgroupInfo]:
        """Get cached cgroup information."""
        return self._cgroup_cache.get(cgroup_id)
