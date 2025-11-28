"""Beautiful web dashboard for container monitoring using Plotly Dash."""

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Optional
from data_collection import ContainerDataCollector


class WebDashboard:
    """Beautiful web dashboard for container monitoring."""

    def __init__(
        self,
        collector: ContainerDataCollector,
        selected_cgroup: Optional[int] = None,
        host: str = "0.0.0.0",
        port: int = 8050,
    ):
        self.collector = collector
        self.selected_cgroup = selected_cgroup
        self.host = host
        self.port = port

        # Suppress Dash dev tools and debug output
        self.app = dash.Dash(
            __name__,
            title="pythonBPF Container Monitor",
            suppress_callback_exceptions=True,
        )

        self._setup_layout()
        self._setup_callbacks()
        self._running = False

    def _setup_layout(self):
        """Create the dashboard layout."""
        self.app.layout = html.Div(
            [
                # Futuristic Header with pythonBPF branding
                html.Div(
                    [
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.Span(
                                            "python",
                                            style={
                                                "fontSize": "52px",
                                                "fontWeight": "300",
                                                "color": "#00ff88",
                                                "fontFamily": "'Courier New', monospace",
                                                "textShadow": "0 0 20px rgba(0,255,136,0.5)",
                                            },
                                        ),
                                        html.Span(
                                            "BPF",
                                            style={
                                                "fontSize": "52px",
                                                "fontWeight": "900",
                                                "color": "#00d4ff",
                                                "fontFamily": "'Courier New', monospace",
                                                "textShadow": "0 0 20px rgba(0,212,255,0.5)",
                                            },
                                        ),
                                    ],
                                    style={"marginBottom": "5px"},
                                ),
                                html.Div(
                                    "CONTAINER PERFORMANCE MONITOR",
                                    style={
                                        "fontSize": "16px",
                                        "letterSpacing": "8px",
                                        "color": "#8899ff",
                                        "fontWeight": "300",
                                        "fontFamily": "'Courier New', monospace",
                                    },
                                ),
                            ],
                            style={
                                "textAlign": "center",
                            },
                        ),
                        html.Div(
                            id="cgroup-name",
                            style={
                                "textAlign": "center",
                                "color": "#00ff88",
                                "fontSize": "20px",
                                "marginTop": "15px",
                                "fontFamily": "'Courier New', monospace",
                                "fontWeight": "bold",
                                "textShadow": "0 0 10px rgba(0,255,136,0.3)",
                            },
                        ),
                    ],
                    style={
                        "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0a0e27 100%)",
                        "padding": "40px 20px",
                        "borderRadius": "0",
                        "marginBottom": "0",
                        "boxShadow": "0 10px 40px rgba(0,212,255,0.2)",
                        "border": "1px solid rgba(0,212,255,0.3)",
                        "borderTop": "3px solid #00d4ff",
                        "borderBottom": "3px solid #00ff88",
                        "position": "relative",
                        "overflow": "hidden",
                    },
                ),
                # Cgroup selector (if no cgroup selected)
                html.Div(
                    [
                        html.Label(
                            "SELECT CGROUP:",
                            style={
                                "fontSize": "14px",
                                "fontWeight": "bold",
                                "color": "#00d4ff",
                                "marginRight": "15px",
                                "fontFamily": "'Courier New', monospace",
                                "letterSpacing": "2px",
                            },
                        ),
                        dcc.Dropdown(
                            id="cgroup-selector",
                            style={
                                "width": "600px",
                                "display": "inline-block",
                                "background": "#1a1f3a",
                                "border": "1px solid #00d4ff",
                            },
                        ),
                    ],
                    id="selector-container",
                    style={
                        "textAlign": "center",
                        "marginTop": "30px",
                        "marginBottom": "30px",
                        "padding": "20px",
                        "background": "rgba(26,31,58,0.5)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(0,212,255,0.2)",
                        "display": "block" if self.selected_cgroup is None else "none",
                    },
                ),
                # Stats cards row
                html.Div(
                    [
                        self._create_stat_card(
                            "syscall-card", "⚡ SYSCALLS", "#00ff88"
                        ),
                        self._create_stat_card("network-card", "🌐 NETWORK", "#00d4ff"),
                        self._create_stat_card("file-card", "💾 FILE I/O", "#ff0088"),
                    ],
                    style={
                        "display": "flex",
                        "justifyContent": "space-around",
                        "marginBottom": "30px",
                        "marginTop": "30px",
                        "gap": "25px",
                        "flexWrap": "wrap",
                        "padding": "0 20px",
                    },
                ),
                # Graphs container
                html.Div(
                    [
                        # Network graphs
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.Span("🌐 ", style={"fontSize": "24px"}),
                                        html.Span(
                                            "NETWORK",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "fontWeight": "bold",
                                            },
                                        ),
                                        html.Span(
                                            " I/O",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "color": "#00d4ff",
                                            },
                                        ),
                                    ],
                                    style={
                                        "color": "#ffffff",
                                        "fontSize": "20px",
                                        "borderBottom": "2px solid #00d4ff",
                                        "paddingBottom": "15px",
                                        "marginBottom": "25px",
                                        "textShadow": "0 0 10px rgba(0,212,255,0.3)",
                                    },
                                ),
                                dcc.Graph(
                                    id="network-graph", style={"height": "400px"}
                                ),
                            ],
                            style={
                                "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)",
                                "padding": "30px",
                                "borderRadius": "15px",
                                "boxShadow": "0 8px 32px rgba(0,212,255,0.15)",
                                "marginBottom": "30px",
                                "border": "1px solid rgba(0,212,255,0.2)",
                            },
                        ),
                        # File I/O graphs
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.Span("💾 ", style={"fontSize": "24px"}),
                                        html.Span(
                                            "FILE",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "fontWeight": "bold",
                                            },
                                        ),
                                        html.Span(
                                            " I/O",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "color": "#ff0088",
                                            },
                                        ),
                                    ],
                                    style={
                                        "color": "#ffffff",
                                        "fontSize": "20px",
                                        "borderBottom": "2px solid #ff0088",
                                        "paddingBottom": "15px",
                                        "marginBottom": "25px",
                                        "textShadow": "0 0 10px rgba(255,0,136,0.3)",
                                    },
                                ),
                                dcc.Graph(
                                    id="file-io-graph", style={"height": "400px"}
                                ),
                            ],
                            style={
                                "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)",
                                "padding": "30px",
                                "borderRadius": "15px",
                                "boxShadow": "0 8px 32px rgba(255,0,136,0.15)",
                                "marginBottom": "30px",
                                "border": "1px solid rgba(255,0,136,0.2)",
                            },
                        ),
                        # Combined time series
                        html.Div(
                            [
                                html.Div(
                                    [
                                        html.Span("📈 ", style={"fontSize": "24px"}),
                                        html.Span(
                                            "REAL-TIME",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "fontWeight": "bold",
                                            },
                                        ),
                                        html.Span(
                                            " METRICS",
                                            style={
                                                "fontFamily": "'Courier New', monospace",
                                                "letterSpacing": "3px",
                                                "color": "#00ff88",
                                            },
                                        ),
                                    ],
                                    style={
                                        "color": "#ffffff",
                                        "fontSize": "20px",
                                        "borderBottom": "2px solid #00ff88",
                                        "paddingBottom": "15px",
                                        "marginBottom": "25px",
                                        "textShadow": "0 0 10px rgba(0,255,136,0.3)",
                                    },
                                ),
                                dcc.Graph(
                                    id="timeseries-graph", style={"height": "500px"}
                                ),
                            ],
                            style={
                                "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)",
                                "padding": "30px",
                                "borderRadius": "15px",
                                "boxShadow": "0 8px 32px rgba(0,255,136,0.15)",
                                "border": "1px solid rgba(0,255,136,0.2)",
                            },
                        ),
                    ],
                    style={"padding": "0 20px"},
                ),
                # Footer with pythonBPF branding
                html.Div(
                    [
                        html.Div(
                            [
                                html.Span(
                                    "Powered by ",
                                    style={"color": "#8899ff", "fontSize": "12px"},
                                ),
                                html.Span(
                                    "pythonBPF",
                                    style={
                                        "color": "#00d4ff",
                                        "fontSize": "14px",
                                        "fontWeight": "bold",
                                        "fontFamily": "'Courier New', monospace",
                                    },
                                ),
                                html.Span(
                                    " | eBPF Container Monitoring",
                                    style={
                                        "color": "#8899ff",
                                        "fontSize": "12px",
                                        "marginLeft": "10px",
                                    },
                                ),
                            ]
                        )
                    ],
                    style={
                        "textAlign": "center",
                        "padding": "20px",
                        "marginTop": "40px",
                        "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)",
                        "borderTop": "1px solid rgba(0,212,255,0.2)",
                    },
                ),
                # Auto-update interval
                dcc.Interval(id="interval-component", interval=1000, n_intervals=0),
            ],
            style={
                "padding": "0",
                "fontFamily": "'Segoe UI', 'Courier New', monospace",
                "background": "linear-gradient(to bottom, #050813 0%, #0a0e27 100%)",
                "minHeight": "100vh",
                "margin": "0",
            },
        )

    def _create_stat_card(self, card_id: str, title: str, color: str):
        """Create a statistics card with futuristic styling."""
        return html.Div(
            [
                html.H3(
                    title,
                    style={
                        "color": color,
                        "fontSize": "16px",
                        "marginBottom": "20px",
                        "fontWeight": "bold",
                        "fontFamily": "'Courier New', monospace",
                        "letterSpacing": "2px",
                        "textShadow": f"0 0 10px {color}50",
                    },
                ),
                html.Div(
                    [
                        html.Div(
                            id=f"{card_id}-value",
                            style={
                                "fontSize": "42px",
                                "fontWeight": "bold",
                                "color": "#ffffff",
                                "marginBottom": "10px",
                                "fontFamily": "'Courier New', monospace",
                                "textShadow": f"0 0 20px {color}40",
                            },
                        ),
                        html.Div(
                            id=f"{card_id}-rate",
                            style={
                                "fontSize": "14px",
                                "color": "#8899ff",
                                "fontFamily": "'Courier New', monospace",
                            },
                        ),
                    ]
                ),
            ],
            style={
                "flex": "1",
                "minWidth": "280px",
                "background": "linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)",
                "padding": "30px",
                "borderRadius": "15px",
                "boxShadow": f"0 8px 32px {color}20",
                "border": f"1px solid {color}40",
                "borderLeft": f"4px solid {color}",
                "transition": "transform 0.3s, box-shadow 0.3s",
                "position": "relative",
                "overflow": "hidden",
            },
        )

    def _setup_callbacks(self):
        """Setup dashboard callbacks."""

        @self.app.callback(
            [Output("cgroup-selector", "options"), Output("cgroup-selector", "value")],
            [Input("interval-component", "n_intervals")],
        )
        def update_cgroup_selector(n):
            if self.selected_cgroup is not None:
                return [], self.selected_cgroup

            cgroups = self.collector.get_all_cgroups()
            options = [
                {"label": f"{cg.name} (ID: {cg.id})", "value": cg.id}
                for cg in sorted(cgroups, key=lambda c: c.name)
            ]
            value = options[0]["value"] if options else None

            if value and self.selected_cgroup is None:
                self.selected_cgroup = value

            return options, self.selected_cgroup

        @self.app.callback(
            Output("cgroup-selector", "value", allow_duplicate=True),
            [Input("cgroup-selector", "value")],
            prevent_initial_call=True,
        )
        def select_cgroup(value):
            if value:
                self.selected_cgroup = value
            return value

        @self.app.callback(
            [
                Output("cgroup-name", "children"),
                Output("syscall-card-value", "children"),
                Output("syscall-card-rate", "children"),
                Output("network-card-value", "children"),
                Output("network-card-rate", "children"),
                Output("file-card-value", "children"),
                Output("file-card-rate", "children"),
                Output("network-graph", "figure"),
                Output("file-io-graph", "figure"),
                Output("timeseries-graph", "figure"),
            ],
            [Input("interval-component", "n_intervals")],
        )
        def update_dashboard(n):
            if self.selected_cgroup is None:
                empty_fig = self._create_empty_figure(
                    "Select a cgroup to begin monitoring"
                )
                return (
                    "SELECT A CGROUP TO START",
                    "0",
                    "",
                    "0 B",
                    "",
                    "0 B",
                    "",
                    empty_fig,
                    empty_fig,
                    empty_fig,
                )

            try:
                stats = self.collector.get_stats_for_cgroup(self.selected_cgroup)
                history = self.collector.get_history(self.selected_cgroup)
                rates = self._calculate_rates(history)

                return (
                    f"► {stats.cgroup_name}",
                    f"{stats.syscall_count:,}",
                    f"{rates['syscalls_per_sec']:.1f} calls/sec",
                    f"{self._format_bytes(stats.rx_bytes + stats.tx_bytes)}",
                    f"↓ {self._format_bytes(rates['rx_bytes_per_sec'])}/s  ↑ {self._format_bytes(rates['tx_bytes_per_sec'])}/s",
                    f"{self._format_bytes(stats.read_bytes + stats.write_bytes)}",
                    f"R: {self._format_bytes(rates['read_bytes_per_sec'])}/s  W: {self._format_bytes(rates['write_bytes_per_sec'])}/s",
                    self._create_network_graph(history),
                    self._create_file_io_graph(history),
                    self._create_timeseries_graph(history),
                )
            except Exception as e:
                empty_fig = self._create_empty_figure(f"Error: {str(e)}")
                return (
                    "ERROR",
                    "0",
                    str(e),
                    "0 B",
                    "",
                    "0 B",
                    "",
                    empty_fig,
                    empty_fig,
                    empty_fig,
                )

    def _create_empty_figure(self, message: str):
        """Create an empty figure with a message."""
        fig = go.Figure()
        fig.update_layout(
            title=message,
            template="plotly_dark",
            paper_bgcolor="#0a0e27",
            plot_bgcolor="#0a0e27",
            font=dict(color="#8899ff", family="Courier New, monospace"),
        )
        return fig

    def _create_network_graph(self, history):
        """Create network I/O graph with futuristic styling."""
        if len(history) < 2:
            return self._create_empty_figure("Collecting data...")

        times = [i for i in range(len(history))]
        rx_bytes = [s.rx_bytes for s in history]
        tx_bytes = [s.tx_bytes for s in history]

        fig = make_subplots(
            rows=2,
            cols=1,
            subplot_titles=("RECEIVED (RX)", "TRANSMITTED (TX)"),
            vertical_spacing=0.15,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=rx_bytes,
                mode="lines",
                name="RX",
                fill="tozeroy",
                line=dict(color="#00d4ff", width=3, shape="spline"),
                fillcolor="rgba(0, 212, 255, 0.2)",
            ),
            row=1,
            col=1,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=tx_bytes,
                mode="lines",
                name="TX",
                fill="tozeroy",
                line=dict(color="#00ff88", width=3, shape="spline"),
                fillcolor="rgba(0, 255, 136, 0.2)",
            ),
            row=2,
            col=1,
        )

        fig.update_xaxes(title_text="Time (samples)", row=2, col=1, color="#8899ff")
        fig.update_yaxes(title_text="Bytes", row=1, col=1, color="#8899ff")
        fig.update_yaxes(title_text="Bytes", row=2, col=1, color="#8899ff")

        fig.update_layout(
            height=400,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0a0e27",
            showlegend=False,
            hovermode="x unified",
            font=dict(family="Courier New, monospace", color="#8899ff"),
        )

        return fig

    def _create_file_io_graph(self, history):
        """Create file I/O graph with futuristic styling."""
        if len(history) < 2:
            return self._create_empty_figure("Collecting data...")

        times = [i for i in range(len(history))]
        read_bytes = [s.read_bytes for s in history]
        write_bytes = [s.write_bytes for s in history]

        fig = make_subplots(
            rows=2,
            cols=1,
            subplot_titles=("READ OPERATIONS", "WRITE OPERATIONS"),
            vertical_spacing=0.15,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=read_bytes,
                mode="lines",
                name="Read",
                fill="tozeroy",
                line=dict(color="#ff0088", width=3, shape="spline"),
                fillcolor="rgba(255, 0, 136, 0.2)",
            ),
            row=1,
            col=1,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=write_bytes,
                mode="lines",
                name="Write",
                fill="tozeroy",
                line=dict(color="#8844ff", width=3, shape="spline"),
                fillcolor="rgba(136, 68, 255, 0.2)",
            ),
            row=2,
            col=1,
        )

        fig.update_xaxes(title_text="Time (samples)", row=2, col=1, color="#8899ff")
        fig.update_yaxes(title_text="Bytes", row=1, col=1, color="#8899ff")
        fig.update_yaxes(title_text="Bytes", row=2, col=1, color="#8899ff")

        fig.update_layout(
            height=400,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0a0e27",
            showlegend=False,
            hovermode="x unified",
            font=dict(family="Courier New, monospace", color="#8899ff"),
        )

        return fig

    def _create_timeseries_graph(self, history):
        """Create combined time series graph with futuristic styling."""
        if len(history) < 2:
            return self._create_empty_figure("Collecting data...")

        times = [i for i in range(len(history))]

        fig = make_subplots(
            rows=3,
            cols=1,
            subplot_titles=(
                "SYSTEM CALLS",
                "NETWORK TRAFFIC (Bytes)",
                "FILE I/O (Bytes)",
            ),
            vertical_spacing=0.1,
            specs=[
                [{"secondary_y": False}],
                [{"secondary_y": True}],
                [{"secondary_y": True}],
            ],
        )

        # Syscalls
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.syscall_count for s in history],
                mode="lines",
                name="Syscalls",
                line=dict(color="#00ff88", width=3, shape="spline"),
            ),
            row=1,
            col=1,
        )

        # Network
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.rx_bytes for s in history],
                mode="lines",
                name="RX",
                line=dict(color="#00d4ff", width=2, shape="spline"),
            ),
            row=2,
            col=1,
            secondary_y=False,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.tx_bytes for s in history],
                mode="lines",
                name="TX",
                line=dict(color="#00ff88", width=2, shape="spline", dash="dot"),
            ),
            row=2,
            col=1,
            secondary_y=True,
        )

        # File I/O
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.read_bytes for s in history],
                mode="lines",
                name="Read",
                line=dict(color="#ff0088", width=2, shape="spline"),
            ),
            row=3,
            col=1,
            secondary_y=False,
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.write_bytes for s in history],
                mode="lines",
                name="Write",
                line=dict(color="#8844ff", width=2, shape="spline", dash="dot"),
            ),
            row=3,
            col=1,
            secondary_y=True,
        )

        fig.update_xaxes(title_text="Time (samples)", row=3, col=1, color="#8899ff")
        fig.update_yaxes(title_text="Count", row=1, col=1, color="#8899ff")
        fig.update_yaxes(
            title_text="RX Bytes", row=2, col=1, secondary_y=False, color="#00d4ff"
        )
        fig.update_yaxes(
            title_text="TX Bytes", row=2, col=1, secondary_y=True, color="#00ff88"
        )
        fig.update_yaxes(
            title_text="Read Bytes", row=3, col=1, secondary_y=False, color="#ff0088"
        )
        fig.update_yaxes(
            title_text="Write Bytes", row=3, col=1, secondary_y=True, color="#8844ff"
        )

        fig.update_layout(
            height=500,
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#0a0e27",
            hovermode="x unified",
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                font=dict(color="#8899ff"),
            ),
            font=dict(family="Courier New, monospace", color="#8899ff"),
        )

        return fig

    def _calculate_rates(self, history):
        """Calculate rates from history."""
        if len(history) < 2:
            return {
                "syscalls_per_sec": 0.0,
                "rx_bytes_per_sec": 0.0,
                "tx_bytes_per_sec": 0.0,
                "read_bytes_per_sec": 0.0,
                "write_bytes_per_sec": 0.0,
            }

        recent = history[-1]
        previous = history[-2]
        time_delta = recent.timestamp - previous.timestamp

        if time_delta <= 0:
            time_delta = 1.0

        return {
            "syscalls_per_sec": max(
                0, (recent.syscall_count - previous.syscall_count) / time_delta
            ),
            "rx_bytes_per_sec": max(
                0, (recent.rx_bytes - previous.rx_bytes) / time_delta
            ),
            "tx_bytes_per_sec": max(
                0, (recent.tx_bytes - previous.tx_bytes) / time_delta
            ),
            "read_bytes_per_sec": max(
                0, (recent.read_bytes - previous.read_bytes) / time_delta
            ),
            "write_bytes_per_sec": max(
                0, (recent.write_bytes - previous.write_bytes) / time_delta
            ),
        }

    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes into human-readable string."""
        if bytes_val < 0:
            bytes_val = 0
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    def run(self):
        """Run the web dashboard."""
        self._running = True
        # Suppress Werkzeug logging
        import logging

        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        self.app.run(debug=False, host=self.host, port=self.port, use_reloader=False)

    def stop(self):
        """Stop the web dashboard."""
        self._running = False
