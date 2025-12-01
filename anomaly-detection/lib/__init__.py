"""
Process Anomaly Detection - Constants and Utilities
"""

import logging

logger = logging.getLogger(__name__)
MAX_SYSCALLS = 548


def comm_for_pid(pid: int) -> bytes | None:
    """Get process name from /proc."""
    try:
        with open(f"/proc/{pid}/comm", "rb") as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.warning(f"Process with PID {pid} not found.")
    except PermissionError:
        logger.warning(f"Permission denied when accessing /proc/{pid}/comm.")
    except Exception as e:
        logger.warning(f"Error reading /proc/{pid}/comm: {e}")
    return None
