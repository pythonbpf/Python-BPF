"""Data collection and management."""

import threading
import time
import numpy as np
from collections import deque
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class LatencyStats:
    """Statistics computed from latency data."""

    total: int = 0
    mean: float = 0.0
    median: float = 0.0
    min: float = 0.0
    max: float = 0.0
    p95: float = 0.0
    p99: float = 0.0

    @classmethod
    def from_array(cls, data: np.ndarray) -> "LatencyStats":
        """Compute stats from numpy array."""
        if len(data) == 0:
            return cls()

        return cls(
            total=len(data),
            mean=float(np.mean(data)),
            median=float(np.median(data)),
            min=float(np.min(data)),
            max=float(np.max(data)),
            p95=float(np.percentile(data, 95)),
            p99=float(np.percentile(data, 99)),
        )


class LatencyCollector:
    """Collects and manages latency data from BPF."""

    def __init__(self, bpf_object, buffer_size: int = 10000):
        self.bpf = bpf_object
        self.all_latencies: List[float] = []
        self.recent_latencies = deque(maxlen=buffer_size)  # type: ignore [var-annotated]
        self.start_time = time.time()
        self._lock = threading.Lock()
        self._poll_thread = None

    def callback(self, cpu: int, event):
        """Callback for BPF events."""
        with self._lock:
            self.all_latencies.append(event.delta_us)
            self.recent_latencies.append(
                {"time": time.time() - self.start_time, "latency": event.delta_us}
            )

    def start(self):
        """Start collecting data."""
        self.bpf["events"].open_perf_buffer(self.callback, struct_name="latency_event")

        def poll_loop():
            while True:
                self.bpf["events"].poll(100)

        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()
        print("✅ Data collection started")

    def get_all_latencies(self) -> np.ndarray:
        """Get all latencies as numpy array."""
        with self._lock:
            return np.array(self.all_latencies) if self.all_latencies else np.array([])

    def get_recent_latencies(self) -> List[Dict]:
        """Get recent latencies with timestamps."""
        with self._lock:
            return list(self.recent_latencies)

    def get_stats(self) -> LatencyStats:
        """Compute current statistics."""
        return LatencyStats.from_array(self.get_all_latencies())

    def get_histogram_buckets(self) -> Dict[int, int]:
        """Get log2 histogram buckets."""
        latencies = self.get_all_latencies()
        if len(latencies) == 0:
            return {}

        log_buckets = np.floor(np.log2(latencies + 1)).astype(int)
        buckets = {}  # type: ignore [var-annotated]
        for bucket in log_buckets:
            buckets[bucket] = buckets.get(bucket, 0) + 1

        return buckets
