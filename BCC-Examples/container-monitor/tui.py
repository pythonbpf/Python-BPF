"""Terminal User Interface for container monitoring."""

import sys
import time
import curses
from typing import Optional, List
from data_collector import ContainerDataCollector, CgroupInfo, ContainerStats


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

        # Header
        title = "🐳 Container Monitor - Select Cgroup"
        stdscr.attron(curses.color_pair(6))
        stdscr.addstr(0, (width - len(title)) // 2, title)
        stdscr.attroff(curses.color_pair(6))

        # Instructions
        instructions = "↑↓: Navigate | ENTER: Select | q: Quit | r: Refresh"
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(1, (width - len(instructions)) // 2, instructions)
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
        list_height = height - 6
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + list_height:
            self.scroll_offset = self.selected_index - list_height + 1

        # Draw cgroup list
        start_y = 3
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(start_y, 2, "─" * (width - 4))
        stdscr.attroff(curses.color_pair(1))

        for i in range(list_height):
            idx = self.scroll_offset + i
            if idx >= len(cgroups):
                break

            cgroup = cgroups[idx]
            y = start_y + 1 + i

            if idx == self.selected_index:
                # Highlight selected
                stdscr.attron(curses.color_pair(2) | curses.A_BOLD | curses.A_REVERSE)
                line = f"► {cgroup.name:<40} ID: {cgroup.id}"
                stdscr.addstr(y, 2, line[:width - 4])
                stdscr.attroff(curses.color_pair(2) | curses.A_BOLD | curses.A_REVERSE)
            else:
                line = f"  {cgroup.name:<40} ID: {cgroup.id}"
                stdscr.addstr(y, 2, line[:width - 4])

        # Footer with count
        footer = f"Total cgroups: {len(cgroups)}"
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

        # Header
        title = f"📊 Monitoring: {stats.cgroup_name}"
        stdscr.attron(curses.color_pair(6))
        stdscr.addstr(0, (width - len(title)) // 2, title)
        stdscr.attroff(curses.color_pair(6))

        # Instructions
        instructions = "ESC/b: Back | q: Quit"
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(1, (width - len(instructions)) // 2, instructions)
        stdscr.attroff(curses.color_pair(3))

        # Syscall count (large number display)
        y = 3
        stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        stdscr.addstr(y, 2, "SYSCALLS")
        stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)

        syscall_str = f"{stats.syscall_count:,}"
        stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
        stdscr.addstr(y + 1, 4, syscall_str)
        stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)

        # Network I/O graphs
        y = 6
        self._draw_section_header(stdscr, y, "NETWORK I/O", 1)

        # RX graph
        y += 2
        rx_label = f"RX: {self._format_bytes(stats.rx_bytes)} ({stats.rx_packets:,} packets)"
        stdscr.addstr(y, 2, rx_label)
        if len(history) > 1:
            self._draw_bar_graph(stdscr, y + 1, 2, width - 4, 3,
                                 [s.rx_bytes for s in history],
                                 curses.color_pair(2))

        # TX graph
        y += 5
        tx_label = f"TX: {self._format_bytes(stats.tx_bytes)} ({stats.tx_packets:,} packets)"
        stdscr.addstr(y, 2, tx_label)
        if len(history) > 1:
            self._draw_bar_graph(stdscr, y + 1, 2, width - 4, 3,
                                 [s.tx_bytes for s in history],
                                 curses.color_pair(3))

        # File I/O graphs
        y += 5
        self._draw_section_header(stdscr, y, "FILE I/O", 1)

        # Read graph
        y += 2
        read_label = f"READ: {self._format_bytes(stats.read_bytes)} ({stats.read_ops:,} ops)"
        stdscr.addstr(y, 2, read_label)
        if len(history) > 1:
            self._draw_bar_graph(stdscr, y + 1, 2, width - 4, 3,
                                 [s.read_bytes for s in history],
                                 curses.color_pair(4))

        # Write graph
        y += 5
        write_label = f"WRITE: {self._format_bytes(stats.write_bytes)} ({stats.write_ops:,} ops)"
        stdscr.addstr(y, 2, write_label)
        if len(history) > 1:
            self._draw_bar_graph(stdscr, y + 1, 2, width - 4, 3,
                                 [s.write_bytes for s in history],
                                 curses.color_pair(5))

    def _draw_section_header(self, stdscr, y: int, title: str, color_pair: int):
        """Draw a section header."""
        height, width = stdscr.getmaxyx()
        stdscr.attron(curses.color_pair(color_pair) | curses.A_BOLD)
        stdscr.addstr(y, 2, title)
        stdscr.addstr(y, len(title) + 3, "─" * (width - len(title) - 5))
        stdscr.attroff(curses.color_pair(color_pair) | curses.A_BOLD)

    def _draw_bar_graph(self, stdscr, y: int, x: int, width: int, height: int,
                        data: List[float], color_pair: int):
        """Draw a simple bar graph."""
        if not data or width < 2:
            return

        # Normalize data to graph width
        max_val = max(data) if max(data) > 0 else 1

        # Take last 'width' data points
        recent_data = data[-width:]

        # Draw bars
        for row in range(height):
            threshold = (height - row) / height
            bar_line = ""

            for val in recent_data:
                normalized = val / max_val
                if normalized >= threshold:
                    bar_line += "█"
                elif normalized >= threshold - 0.2:
                    bar_line += "▓"
                elif normalized >= threshold - 0.4:
                    bar_line += "▒"
                elif normalized >= threshold - 0.6:
                    bar_line += "░"
                else:
                    bar_line += " "

            try:
                stdscr.attron(color_pair)
                stdscr.addstr(y + row, x, bar_line[:width])
                stdscr.attroff(color_pair)
            except:
                pass  # Ignore errors at screen edges

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.
            0
        return f"{bytes_val:.2f} PB"

    def _handle_input(self, key: int) -> bool:
        """Handle keyboard input.  Returns False to exit."""
        if key == ord('q') or key == ord('Q'):
            return False  # Exit

        if self.current_screen == "selection":
            if key == curses.KEY_UP:
                self.selected_index = max(0, self.selected_index - 1)
            elif key == curses.KEY_DOWN:
                cgroups = self.collector.get_all_cgroups()
                self.selected_index = min(len(cgroups) - 1, self.selected_index + 1)
            elif key == ord('\n') or key == curses.KEY_ENTER or key == 10:
                # Select cgroup
                cgroups = self.collector.get_all_cgroups()
                if cgroups and 0 <= self.selected_index < len(cgroups):
                    cgroups.sort(key=lambda c: c.name)
                    self.selected_cgroup = cgroups[self.selected_index].id
                    self.current_screen = "monitoring"
            elif key == ord('r') or key == ord('R'):
                # Force refresh cache
                self.collector._cgroup_cache_time = 0

        elif self.current_screen == "monitoring":
            if key == 27 or key == ord('b') or key == ord('B'):  # ESC or 'b'
                self.current_screen = "selection"
                self.selected_cgroup = None

        return True  # Continue running
