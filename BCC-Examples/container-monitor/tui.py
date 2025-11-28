"""Terminal User Interface for container monitoring."""

import time
import curses
from typing import Optional, List
from data_collection import ContainerDataCollector


class ContainerMonitorTUI:
    """TUI for container monitoring with cgroup selection and live graphs."""

    def __init__(self, collector: ContainerDataCollector):
        self.collector = collector
        self.selected_cgroup: Optional[int] = None
        self.current_screen = "selection"  # "selection" or "monitoring"
        self.selected_index = 0
        self.scroll_offset = 0

    def run(self):
        """Run the TUI application."""
        curses.wrapper(self._main_loop)

    def _main_loop(self, stdscr):
        """Main curses loop."""
        # Configure curses
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(True)  # Non-blocking input
        stdscr.timeout(100)  # Refresh every 100ms

        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_CYAN)

        while True:
            stdscr.clear()

            try:
                if self.current_screen == "selection":
                    self._draw_selection_screen(stdscr)
                elif self.current_screen == "monitoring":
                    self._draw_monitoring_screen(stdscr)

                stdscr.refresh()

                # Handle input
                key = stdscr.getch()
                if key != -1:
                    if not self._handle_input(key):
                        break  # Exit requested

            except KeyboardInterrupt:
                break
            except Exception as e:
                # Show error
                stdscr.addstr(0, 0, f"Error: {str(e)}")
                stdscr.refresh()
                time.sleep(2)

    def _draw_selection_screen(self, stdscr):
        """Draw the cgroup selection screen."""
        height, width = stdscr.getmaxyx()

        # Draw fancy header box
        self._draw_fancy_header(
            stdscr, "🐳 CONTAINER MONITOR", "Select a Cgroup to Monitor"
        )

        # Instructions
        instructions = "↑↓: Navigate | ENTER: Select | q: Quit | r: Refresh"
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(3, (width - len(instructions)) // 2, instructions)
        stdscr.attroff(curses.color_pair(3))

        # Get cgroups
        cgroups = self.collector.get_all_cgroups()

        if not cgroups:
            msg = "No cgroups found.  Waiting for activity..."
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(height // 2, (width - len(msg)) // 2, msg)
            stdscr.attroff(curses.color_pair(4))
            return

        # Sort cgroups by name
        cgroups.sort(key=lambda c: c.name)

        # Adjust selection bounds
        if self.selected_index >= len(cgroups):
            self.selected_index = len(cgroups) - 1
        if self.selected_index < 0:
            self.selected_index = 0

        # Calculate visible range
        list_height = height - 8
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + list_height:
            self.scroll_offset = self.selected_index - list_height + 1

        # Draw cgroup list with fancy borders
        start_y = 5
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(start_y, 2, "╔" + "═" * (width - 6) + "╗")
        stdscr.attroff(curses.color_pair(1))

        for i in range(list_height):
            idx = self.scroll_offset + i
            y = start_y + 1 + i

            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, 2, "║")
            stdscr.addstr(y, width - 3, "║")
            stdscr.attroff(curses.color_pair(1))

            if idx >= len(cgroups):
                continue

            cgroup = cgroups[idx]

            if idx == self.selected_index:
                # Highlight selected with better styling
                stdscr.attron(curses.color_pair(8) | curses.A_BOLD)
                line = f" ► {cgroup.name:<35} │ ID: {cgroup.id} "
                stdscr.addstr(y, 3, line[: width - 6])
                stdscr.attroff(curses.color_pair(8) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(7))
                line = f"   {cgroup.name:<35} │ ID: {cgroup.id} "
                stdscr.addstr(y, 3, line[: width - 6])
                stdscr.attroff(curses.color_pair(7))

        # Bottom border
        bottom_y = start_y + 1 + list_height
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(bottom_y, 2, "╚" + "═" * (width - 6) + "╝")
        stdscr.attroff(curses.color_pair(1))

        # Footer with count and scroll indicator
        footer = f"Total: {len(cgroups)} cgroups"
        if len(cgroups) > list_height:
            footer += f" │ Showing {self.scroll_offset + 1}-{min(self.scroll_offset + list_height, len(cgroups))}"
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(height - 2, (width - len(footer)) // 2, footer)
        stdscr.attroff(curses.color_pair(1))

    def _draw_monitoring_screen(self, stdscr):
        """Draw the monitoring screen for selected cgroup."""
        height, width = stdscr.getmaxyx()

        if self.selected_cgroup is None:
            return

        # Get current stats
        stats = self.collector.get_stats_for_cgroup(self.selected_cgroup)
        history = self.collector.get_history(self.selected_cgroup)

        # Draw fancy header
        self._draw_fancy_header(
            stdscr, f"📊 {stats.cgroup_name}", "Live Performance Metrics"
        )

        # Instructions
        instructions = "ESC/b: Back to List | q: Quit"
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(3, (width - len(instructions)) // 2, instructions)
        stdscr.attroff(curses.color_pair(3))

        # Calculate metrics for rate display
        rates = self._calculate_rates(history)

        y = 5

        # Syscall count in a fancy box
        self._draw_metric_box(
            stdscr,
            y,
            2,
            width - 4,
            "⚡ SYSTEM CALLS",
            f"{stats.syscall_count:,}",
            f"Rate: {rates['syscalls_per_sec']:.1f}/sec",
            curses.color_pair(5),
        )

        y += 4

        # Network I/O Section
        self._draw_section_header(stdscr, y, "🌐 NETWORK I/O", 1)
        y += 1

        # RX graph with legend
        rx_label = f"RX: {self._format_bytes(stats.rx_bytes)}"
        rx_rate = f"{self._format_bytes(rates['rx_bytes_per_sec'])}/s"
        rx_pkts = f"{stats.rx_packets:,} pkts ({rates['rx_pkts_per_sec']:.1f}/s)"

        self._draw_labeled_graph(
            stdscr,
            y,
            2,
            width - 4,
            4,
            rx_label,
            rx_rate,
            rx_pkts,
            [s.rx_bytes for s in history],
            curses.color_pair(2),
            "Received Traffic (last 100 samples)",
        )

        y += 6

        # TX graph with legend
        tx_label = f"TX: {self._format_bytes(stats.tx_bytes)}"
        tx_rate = f"{self._format_bytes(rates['tx_bytes_per_sec'])}/s"
        tx_pkts = f"{stats.tx_packets:,} pkts ({rates['tx_pkts_per_sec']:.1f}/s)"

        self._draw_labeled_graph(
            stdscr,
            y,
            2,
            width - 4,
            4,
            tx_label,
            tx_rate,
            tx_pkts,
            [s.tx_bytes for s in history],
            curses.color_pair(3),
            "Transmitted Traffic (last 100 samples)",
        )

        y += 6

        # File I/O Section
        self._draw_section_header(stdscr, y, "💾 FILE I/O", 1)
        y += 1

        # Read graph with legend
        read_label = f"READ: {self._format_bytes(stats.read_bytes)}"
        read_rate = f"{self._format_bytes(rates['read_bytes_per_sec'])}/s"
        read_ops = f"{stats.read_ops:,} ops ({rates['read_ops_per_sec']:.1f}/s)"

        self._draw_labeled_graph(
            stdscr,
            y,
            2,
            width - 4,
            4,
            read_label,
            read_rate,
            read_ops,
            [s.read_bytes for s in history],
            curses.color_pair(4),
            "Read Operations (last 100 samples)",
        )

        y += 6

        # Write graph with legend
        write_label = f"WRITE: {self._format_bytes(stats.write_bytes)}"
        write_rate = f"{self._format_bytes(rates['write_bytes_per_sec'])}/s"
        write_ops = f"{stats.write_ops:,} ops ({rates['write_ops_per_sec']:.1f}/s)"

        self._draw_labeled_graph(
            stdscr,
            y,
            2,
            width - 4,
            4,
            write_label,
            write_rate,
            write_ops,
            [s.write_bytes for s in history],
            curses.color_pair(5),
            "Write Operations (last 100 samples)",
        )

    def _draw_fancy_header(self, stdscr, title: str, subtitle: str):
        """Draw a fancy header with title and subtitle."""
        height, width = stdscr.getmaxyx()

        # Top border
        stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
        stdscr.addstr(0, 0, "═" * width)

        # Title
        stdscr.addstr(0, (width - len(title)) // 2, f" {title} ")
        stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)

        # Subtitle
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(1, (width - len(subtitle)) // 2, subtitle)
        stdscr.attroff(curses.color_pair(1))

        # Bottom border
        stdscr.attron(curses.color_pair(6))
        stdscr.addstr(2, 0, "═" * width)
        stdscr.attroff(curses.color_pair(6))

    def _draw_metric_box(
        self,
        stdscr,
        y: int,
        x: int,
        width: int,
        label: str,
        value: str,
        detail: str,
        color_pair: int,
    ):
        """Draw a fancy box for displaying a metric."""
        # Top border
        stdscr.attron(color_pair | curses.A_BOLD)
        stdscr.addstr(y, x, "┌" + "─" * (width - 2) + "┐")

        # Label
        stdscr.addstr(y + 1, x, "│")
        stdscr.addstr(y + 1, x + 2, label)
        stdscr.addstr(y + 1, x + width - 1, "│")

        # Value (large)
        stdscr.addstr(y + 2, x, "│")
        stdscr.attroff(color_pair | curses.A_BOLD)
        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(y + 2, x + 4, value)
        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
        stdscr.attron(color_pair | curses.A_BOLD)
        stdscr.addstr(y + 2, x + width - 1, "│")

        # Detail
        stdscr.addstr(y + 2, x + width - len(detail) - 3, detail)

        # Bottom border
        stdscr.addstr(y + 3, x, "└" + "─" * (width - 2) + "┘")
        stdscr.attroff(color_pair | curses.A_BOLD)

    def _draw_section_header(self, stdscr, y: int, title: str, color_pair: int):
        """Draw a section header."""
        height, width = stdscr.getmaxyx()
        stdscr.attron(curses.color_pair(color_pair) | curses.A_BOLD)
        stdscr.addstr(y, 2, title)
        stdscr.addstr(y, len(title) + 3, "─" * (width - len(title) - 5))
        stdscr.attroff(curses.color_pair(color_pair) | curses.A_BOLD)

    def _draw_labeled_graph(
        self,
        stdscr,
        y: int,
        x: int,
        width: int,
        height: int,
        label: str,
        rate: str,
        detail: str,
        data: List[float],
        color_pair: int,
        description: str,
    ):
        """Draw a graph with labels and legend."""
        # Header with metrics
        stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(y, x, label)
        stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        stdscr.attron(curses.color_pair(2))
        stdscr.addstr(y, x + len(label) + 2, rate)
        stdscr.attroff(curses.color_pair(2))

        stdscr.attron(curses.color_pair(7))
        stdscr.addstr(y, x + len(label) + len(rate) + 4, detail)
        stdscr.attroff(curses.color_pair(7))

        # Draw the graph
        if len(data) > 1:
            self._draw_bar_graph_enhanced(
                stdscr, y + 1, x, width, height, data, color_pair
            )
        else:
            stdscr.attron(curses.color_pair(7))
            stdscr.addstr(y + 2, x + 2, "Collecting data...")
            stdscr.attroff(curses.color_pair(7))

        # Graph legend at bottom
        stdscr.attron(curses.color_pair(7))
        stdscr.addstr(y + height + 1, x, f"└─ {description}")
        stdscr.attroff(curses.color_pair(7))

    def _draw_bar_graph_enhanced(
        self,
        stdscr,
        y: int,
        x: int,
        width: int,
        height: int,
        data: List[float],
        color_pair: int,
    ):
        """Draw an enhanced bar graph with axis and scale."""
        if not data or width < 2:
            return

        # Calculate statistics
        max_val = max(data) if max(data) > 0 else 1
        min_val = min(data)
        avg_val = sum(data) / len(data)

        # Take last 'width - 10' data points (leave room for Y-axis)
        graph_width = width - 12
        recent_data = data[-graph_width:] if len(data) > graph_width else data

        # Draw Y-axis labels
        stdscr.attron(curses.color_pair(7))
        stdscr.addstr(y, x, f"│{self._format_bytes(max_val):>9}")
        stdscr.addstr(y + height // 2, x, f"│{self._format_bytes(avg_val):>9}")
        stdscr.addstr(y + height - 1, x, f"│{self._format_bytes(min_val):>9}")
        stdscr.attroff(curses.color_pair(7))

        # Draw bars
        for row in range(height):
            threshold = (height - row) / height
            bar_line = ""

            for val in recent_data:
                normalized = val / max_val if max_val > 0 else 0
                if normalized >= threshold:
                    bar_line += "█"
                elif normalized >= threshold - 0.15:
                    bar_line += "▓"
                elif normalized >= threshold - 0.35:
                    bar_line += "▒"
                elif normalized >= threshold - 0.5:
                    bar_line += "░"
                else:
                    bar_line += " "

            stdscr.attron(color_pair)
            stdscr.addstr(y + row, x + 11, bar_line)
            stdscr.attroff(color_pair)

        # Draw X-axis
        stdscr.attron(curses.color_pair(7))
        stdscr.addstr(y + height, x + 10, "├" + "─" * len(recent_data))
        stdscr.addstr(y + height, x + 10 + len(recent_data), "→ time")
        stdscr.attroff(curses.color_pair(7))

    def _calculate_rates(self, history: List) -> dict:
        """Calculate per-second rates from history."""
        if len(history) < 2:
            return {
                "syscalls_per_sec": 0.0,
                "rx_bytes_per_sec": 0.0,
                "tx_bytes_per_sec": 0.0,
                "rx_pkts_per_sec": 0.0,
                "tx_pkts_per_sec": 0.0,
                "read_bytes_per_sec": 0.0,
                "write_bytes_per_sec": 0.0,
                "read_ops_per_sec": 0.0,
                "write_ops_per_sec": 0.0,
            }

        # Calculate delta between last two samples
        recent = history[-1]
        previous = history[-2]
        time_delta = recent.timestamp - previous.timestamp

        if time_delta <= 0:
            time_delta = 1.0

        return {
            "syscalls_per_sec": (recent.syscall_count - previous.syscall_count)
            / time_delta,
            "rx_bytes_per_sec": (recent.rx_bytes - previous.rx_bytes) / time_delta,
            "tx_bytes_per_sec": (recent.tx_bytes - previous.tx_bytes) / time_delta,
            "rx_pkts_per_sec": (recent.rx_packets - previous.rx_packets) / time_delta,
            "tx_pkts_per_sec": (recent.tx_packets - previous.tx_packets) / time_delta,
            "read_bytes_per_sec": (recent.read_bytes - previous.read_bytes)
            / time_delta,
            "write_bytes_per_sec": (recent.write_bytes - previous.write_bytes)
            / time_delta,
            "read_ops_per_sec": (recent.read_ops - previous.read_ops) / time_delta,
            "write_ops_per_sec": (recent.write_ops - previous.write_ops) / time_delta,
        }

    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes into human-readable string."""
        if bytes_val < 0:
            bytes_val = 0
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f}PB"

    def _handle_input(self, key: int) -> bool:
        """Handle keyboard input. Returns False to exit."""
        if key == ord("q") or key == ord("Q"):
            return False  # Exit

        if self.current_screen == "selection":
            if key == curses.KEY_UP:
                self.selected_index = max(0, self.selected_index - 1)
            elif key == curses.KEY_DOWN:
                cgroups = self.collector.get_all_cgroups()
                self.selected_index = min(len(cgroups) - 1, self.selected_index + 1)
            elif key == ord("\n") or key == curses.KEY_ENTER or key == 10:
                # Select cgroup
                cgroups = self.collector.get_all_cgroups()
                if cgroups and 0 <= self.selected_index < len(cgroups):
                    cgroups.sort(key=lambda c: c.name)
                    self.selected_cgroup = cgroups[self.selected_index].id
                    self.current_screen = "monitoring"
            elif key == ord("r") or key == ord("R"):
                # Force refresh cache
                self.collector._cgroup_cache_time = 0

        elif self.current_screen == "monitoring":
            if key == 27 or key == ord("b") or key == ord("B"):  # ESC or 'b'
                self.current_screen = "selection"
                self.selected_cgroup = None

        return True  # Continue running
