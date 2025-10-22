from pythonbpf import bpf, map, struct, section, bpfglobal, BPF
from pythonbpf.helper import ktime, pid
from pythonbpf.maps import HashMap, PerfEventArray
from ctypes import c_void_p, c_uint64

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
import numpy as np
import threading
import time
from collections import Counter

# ==================== BPF Setup ====================


@bpf
@struct
class latency_event:
    pid: c_uint64
    delta_us: c_uint64


@bpf
@map
def start() -> HashMap:
    return HashMap(key=c_uint64, value=c_uint64, max_entries=10240)


@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_uint64, value_size=c_uint64)


@bpf
@section("kprobe/vfs_read")
def do_entry(ctx: c_void_p) -> c_uint64:
    p, ts = pid(), ktime()
    start.update(p, ts)
    return 0  # type: ignore [return-value]


@bpf
@section("kretprobe/vfs_read")
def do_return(ctx: c_void_p) -> c_uint64:
    p = pid()
    tsp = start.lookup(p)

    if tsp:
        delta_ns = ktime() - tsp

        if delta_ns > 1000:
            evt = latency_event()
            evt.pid, evt.delta_us = p, delta_ns // 1000
            events.output(evt)

        start.delete(p)

    return 0  # type: ignore [return-value]


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


console = Console()
console.print("[bold green]Loading BPF program...[/]")

b = BPF()
b.load()
b.attach_all()

# ==================== Data Collection ====================

all_latencies = []
histogram_buckets = Counter()  # type: ignore [var-annotated]


def callback(cpu, event):
    all_latencies.append(event.delta_us)
    # Create log2 bucket
    bucket = int(np.floor(np.log2(event.delta_us + 1)))
    histogram_buckets[bucket] += 1


b["events"].open_perf_buffer(callback, struct_name="latency_event")


def poll_events():
    while True:
        b["events"].poll(100)


poll_thread = threading.Thread(target=poll_events, daemon=True)
poll_thread.start()

# ==================== Live Display ====================


def generate_display():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=8),
        Layout(name="histogram", size=20),
    )

    # Header
    layout["header"].update(
        Panel("[bold cyan]🔥 VFS Read Latency Monitor[/]", style="bold white on blue")
    )

    # Stats
    if len(all_latencies) > 0:
        lats = np.array(all_latencies)
        stats_table = Table(show_header=False, box=None, padding=(0, 2))
        stats_table.add_column(style="bold cyan")
        stats_table.add_column(style="bold yellow")

        stats_table.add_row("📊 Total Samples:", f"{len(lats):,}")
        stats_table.add_row("⚡ Mean Latency:", f"{np.mean(lats):.2f} µs")
        stats_table.add_row("📉 Min Latency:", f"{np.min(lats):.2f} µs")
        stats_table.add_row("📈 Max Latency:", f"{np.max(lats):.2f} µs")
        stats_table.add_row("🎯 P95 Latency:", f"{np.percentile(lats, 95):.2f} µs")
        stats_table.add_row("🔥 P99 Latency:", f"{np.percentile(lats, 99):.2f} µs")

        layout["stats"].update(
            Panel(stats_table, title="Statistics", border_style="green")
        )
    else:
        layout["stats"].update(
            Panel("[yellow]Waiting for data...[/]", border_style="yellow")
        )

    # Histogram
    if histogram_buckets:
        hist_table = Table(title="Latency Distribution", box=None)
        hist_table.add_column("Range", style="cyan", no_wrap=True)
        hist_table.add_column("Count", justify="right", style="yellow")
        hist_table.add_column("Distribution", style="green")

        max_count = max(histogram_buckets.values())

        for bucket in sorted(histogram_buckets.keys()):
            count = histogram_buckets[bucket]
            lower = 2**bucket
            upper = 2 ** (bucket + 1)

            # Create bar
            bar_width = int((count / max_count) * 40)
            bar = "█" * bar_width

            hist_table.add_row(
                f"{lower:5d}-{upper:5d} µs",
                f"{count:6d}",
                f"[green]{bar}[/] {count / len(all_latencies) * 100:.1f}%",
            )

        layout["histogram"].update(Panel(hist_table, border_style="green"))

    return layout


try:
    with Live(generate_display(), refresh_per_second=2, console=console) as live:
        while True:
            time.sleep(0.5)
            live.update(generate_display())
except KeyboardInterrupt:
    console.print("\n[bold red]Stopping...[/]")

    if all_latencies:
        console.print(f"\n[bold green]✅ Collected {len(all_latencies):,} samples[/]")
