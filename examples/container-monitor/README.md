# Container Monitor TUI

A beautiful terminal-based container monitoring tool that combines syscall tracking, file I/O monitoring, and network traffic analysis using eBPF.

## Features

- 🎯 **Interactive Cgroup Selection** - Navigate and select cgroups with arrow keys
- 📊 **Real-time Monitoring** - Live graphs and statistics
- 🔥 **Syscall Tracking** - Total syscall count per cgroup
- 💾 **File I/O Monitoring** - Read/write operations and bytes with graphs
- 🌐 **Network Traffic** - RX/TX packets and bytes with live graphs
- ⚡ **Efficient Caching** - Reduced /proc lookups for better performance
- 🎨 **Beautiful TUI** - Clean, colorful terminal interface

## Requirements

- Python 3.7+
- pythonbpf
- Root privileges (for eBPF)

## Installation

```bash
# Ensure you have pythonbpf installed
pip install pythonbpf

# Run the monitor
sudo $(which python) container_monitor.py
```

## Usage

1. **Selection Screen**: Use ↑↓ arrow keys to navigate through cgroups, press ENTER to select
2. **Monitoring Screen**: View real-time graphs and statistics, press ESC or 'b' to go back
3. **Exit**: Press 'q' at any time to quit

## Architecture

- `container_monitor.py` - Main BPF program combining all three tracers
- `data_collector.py` - Data collection, caching, and history management
- `tui. py` - Terminal user interface with selection and monitoring screens

## BPF Programs

- **vfs_read/vfs_write** - Track file I/O operations
- **__netif_receive_skb/__dev_queue_xmit** - Track network traffic
- **raw_syscalls/sys_enter** - Count all syscalls

All programs filter by cgroup ID for per-container monitoring.
