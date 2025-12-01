#!/usr/bin/env python3
"""
Process Behavior Anomaly Detection using PythonBPF and Autoencoders

Ported from evilsocket's BCC implementation to PythonBPF.
https://github.com/evilsocket/ebpf-process-anomaly-detection

Usage:
    # 1.Learn normal behavior from a process
    sudo python main.py --learn --pid 1234 --data normal.csv

    # 2.Train the autoencoder (no sudo needed)
    python main.py --train --data normal.csv --model model.h5

    # 3.Monitor for anomalies
    sudo python main.py --run --pid 1234 --model model.h5
"""

import argparse
import logging
import os
import sys
import time
from collections import Counter

from lib import MAX_SYSCALLS
from lib.ml import AutoEncoder
from lib.platform import SYSCALLS
from lib.probe import Probe

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def learn(pid: int, data_path: str, poll_interval_ms: int) -> None:
    """
    Capture syscall patterns from target process.

    Args:
        pid: Target process ID
        data_path: Path to save CSV data
        poll_interval_ms: Polling interval in milliseconds
    """
    if os.path.exists(data_path):
        logger.error(
            f"{data_path} already exists.Delete it or use a different filename."
        )
        sys.exit(1)

    try:
        probe = Probe(pid)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    probe_comm = probe.comm.decode() if probe.comm else "unknown"

    print(f"📊 Learning from process {pid} ({probe_comm})")
    print(f"📁 Saving data to {data_path}")
    print(f"⏱️  Polling interval: {poll_interval_ms}ms")
    print("Press Ctrl+C to stop...\n")

    probe.start()

    prev_histogram = [0.0] * MAX_SYSCALLS
    prev_report_time = time.time()
    sample_count = 0
    poll_interval_sec = poll_interval_ms / 1000.0

    header = "sample_time," + ",".join(f"sys_{i}" for i in range(MAX_SYSCALLS))

    with open(data_path, "w") as fp:
        fp.write(header + "\n")

        try:
            while True:
                histogram = [float(x) for x in probe.get_histogram()]

                if histogram != prev_histogram:
                    deltas = _compute_deltas(prev_histogram, histogram)
                    prev_histogram = histogram.copy()

                    row = f"{time.time()},{','.join(map(str, deltas))}"
                    fp.write(row + "\n")
                    fp.flush()
                    sample_count += 1

                now = time.time()
                if now - prev_report_time >= 1.0:
                    print(f"  {sample_count} samples saved...")
                    prev_report_time = now

                time.sleep(poll_interval_sec)

        except KeyboardInterrupt:
            print(f"\n✅ Stopped. Saved {sample_count} samples to {data_path}")


def train(data_path: str, model_path: str, epochs: int, batch_size: int) -> None:
    """
    Train autoencoder on captured data.

    Args:
        data_path: Path to training CSV data
        model_path: Path to save trained model
        epochs: Number of training epochs
        batch_size: Training batch size
    """
    if not os.path.exists(data_path):
        logger.error(f"Data file {data_path} not found.Run --learn first.")
        sys.exit(1)

    print(f"🧠 Training autoencoder on {data_path}")
    print(f"   Epochs: {epochs}")
    print(f"   Batch size: {batch_size}")
    print()

    ae = AutoEncoder(model_path)
    _, threshold = ae.train(data_path, epochs, batch_size)

    print()
    print("=" * 50)
    print("✅ Training complete!")
    print(f"   Model saved to: {model_path}")
    print(f"   Error threshold: {threshold:.6f}")
    print()
    print(f"💡 Use --max-error {threshold:.4f} when running detection")
    print("=" * 50)


def run(pid: int, model_path: str, max_error: float, poll_interval_ms: int) -> None:
    """
    Monitor process and detect anomalies.

    Args:
        pid: Target process ID
        model_path: Path to trained model
        max_error: Anomaly detection threshold
        poll_interval_ms: Polling interval in milliseconds
    """
    if not os.path.exists(model_path):
        logger.error(f"Model file {model_path} not found. Run --train first.")
        sys.exit(1)

    try:
        probe = Probe(pid)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    ae = AutoEncoder(model_path, load=True)
    probe_comm = probe.comm.decode() if probe.comm else "unknown"

    print(f"🔍 Monitoring process {pid} ({probe_comm}) for anomalies")
    print(f"   Error threshold: {max_error}")
    print(f"   Polling interval: {poll_interval_ms}ms")
    print("Press Ctrl+C to stop...\n")

    probe.start()

    prev_histogram = [0.0] * MAX_SYSCALLS
    anomaly_count = 0
    check_count = 0
    poll_interval_sec = poll_interval_ms / 1000.0

    try:
        while True:
            histogram = [float(x) for x in probe.get_histogram()]

            if histogram != prev_histogram:
                deltas = _compute_deltas(prev_histogram, histogram)
                prev_histogram = histogram.copy()
                check_count += 1

                _, feat_errors, total_error = ae.predict([deltas])

                if total_error > max_error:
                    anomaly_count += 1
                    _report_anomaly(anomaly_count, total_error, max_error, feat_errors)

            time.sleep(poll_interval_sec)

    except KeyboardInterrupt:
        print("\n✅ Stopped.")
        print(f"   Checks performed: {check_count}")
        print(f"   Anomalies detected: {anomaly_count}")


def _compute_deltas(prev: list[float], current: list[float]) -> list[float]:
    """Compute rate of change between two histograms."""
    deltas = []
    for p, c in zip(prev, current):
        if c != 0.0:
            delta = 1.0 - (p / c)
        else:
            delta = 0.0
        deltas.append(delta)
    return deltas


def _report_anomaly(
    count: int,
    total_error: float,
    threshold: float,
    feat_errors: list[float],
) -> None:
    """Print anomaly report with top offending syscalls."""
    print(f"🚨 ANOMALY #{count} detected!")
    print(f"   Total error: {total_error:.4f} (threshold: {threshold})")

    errors_by_syscall = {idx: err for idx, err in enumerate(feat_errors)}
    top3 = Counter(errors_by_syscall).most_common(3)

    print("   Top anomalous syscalls:")
    for idx, err in top3:
        name = SYSCALLS.get(idx, f"syscall_{idx}")
        print(f"     • {name!r}: {err:.4f}")
    print()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Process anomaly detection with PythonBPF and Autoencoders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Learn from a process (e.g., Firefox) for a few minutes
  sudo python main.py --learn --pid $(pgrep -o firefox) --data firefox.csv

  # Train the model (no sudo needed)
  python main.py --train --data firefox.csv --model firefox.h5

  # Monitor the same process for anomalies
  sudo python main.py --run --pid $(pgrep -o firefox) --model firefox.h5

  # Full workflow for nginx:
  sudo python main.py --learn --pid $(pgrep -o nginx) --data nginx_normal.csv
  python main.py --train --data nginx_normal.csv --model nginx.h5 --epochs 100
  sudo python main.py --run --pid $(pgrep -o nginx) --model nginx.h5 --max-error 0.05
        """,
    )

    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--learn",
        action="store_true",
        help="Capture syscall patterns from a process",
    )
    actions.add_argument(
        "--train",
        action="store_true",
        help="Train autoencoder on captured data",
    )
    actions.add_argument(
        "--run",
        action="store_true",
        help="Monitor process for anomalies",
    )

    parser.add_argument(
        "--pid",
        type=int,
        default=0,
        help="Target process ID",
    )
    parser.add_argument(
        "--data",
        default="data.csv",
        help="CSV file for training data (default: data.csv)",
    )
    parser.add_argument(
        "--model",
        default="model.keras",
        help="Model file path (default: model.h5)",
    )
    parser.add_argument(
        "--time",
        type=int,
        default=100,
        help="Polling interval in milliseconds (default: 100)",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=200,
        help="Training epochs (default: 200)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Training batch size (default: 16)",
    )
    parser.add_argument(
        "--max-error",
        type=float,
        default=0.09,
        help="Anomaly detection threshold (default: 0.09)",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not any([args.learn, args.train, args.run]):
        print("No action specified.Use --learn, --train, or --run.")
        print("Run with --help for usage information.")
        sys.exit(0)

    if args.learn:
        if args.pid == 0:
            logger.error("--pid required for --learn")
            sys.exit(1)
        learn(args.pid, args.data, args.time)

    elif args.train:
        train(args.data, args.model, args.epochs, args.batch_size)

    elif args.run:
        if args.pid == 0:
            logger.error("--pid required for --run")
            sys.exit(1)
        run(args.pid, args.model, args.max_error, args.time)


if __name__ == "__main__":
    main()
