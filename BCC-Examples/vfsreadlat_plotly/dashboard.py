"""Plotly Dash dashboard for visualizing latency data."""

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np


class LatencyDashboard:
    """Interactive dashboard for latency visualization."""

    def __init__(self, collector, title: str = "VFS Read Latency Monitor"):
        self.collector = collector
        self.app = dash.Dash(__name__)
        self.app.title = title
        self._setup_layout()
        self._setup_callbacks()

    def _setup_layout(self):
        """Create dashboard layout."""
        self.app.layout = html.Div(
            [
                html.H1(
                    "🔥 VFS Read Latency Dashboard",
                    style={
                        "textAlign": "center",
                        "color": "#2c3e50",
                        "marginBottom": 20,
                    },
                ),
                # Stats cards
                html.Div(
                    [
                        self._create_stat_card(
                            "total-samples", "📊 Total Samples", "#3498db"
                        ),
                        self._create_stat_card(
                            "mean-latency", "⚡ Mean Latency", "#e74c3c"
                        ),
                        self._create_stat_card(
                            "p99-latency", "🔥 P99 Latency", "#f39c12"
                        ),
                    ],
                    style={
                        "display": "flex",
                        "justifyContent": "space-around",
                        "marginBottom": 30,
                    },
                ),
                # Graphs - ✅ Make sure these IDs match the callback outputs
                dcc.Graph(id="dual-histogram", style={"height": "450px"}),
                dcc.Graph(id="log2-buckets", style={"height": "350px"}),
                dcc.Graph(id="timeseries-graph", style={"height": "300px"}),
                # Auto-update
                dcc.Interval(id="interval-component", interval=1000, n_intervals=0),
            ],
            style={"padding": 20, "fontFamily": "Arial, sans-serif"},
        )

    def _create_stat_card(self, id_name: str, title: str, color: str):
        """Create a statistics card."""
        return html.Div(
            [
                html.H3(title, style={"color": color}),
                html.H2(id=id_name, style={"fontSize": 48, "color": "#2c3e50"}),
            ],
            className="stat-box",
            style={
                "background": "white",
                "padding": 20,
                "borderRadius": 10,
                "boxShadow": "0 4px 6px rgba(0,0,0,0.1)",
                "textAlign": "center",
                "flex": 1,
                "margin": "0 10px",
            },
        )

    def _setup_callbacks(self):
        """Setup dashboard callbacks."""

        @self.app.callback(
            [
                Output("total-samples", "children"),
                Output("mean-latency", "children"),
                Output("p99-latency", "children"),
                Output("dual-histogram", "figure"),  # ✅ Match layout IDs
                Output("log2-buckets", "figure"),  # ✅ Match layout IDs
                Output("timeseries-graph", "figure"),  # ✅ Match layout IDs
            ],
            [Input("interval-component", "n_intervals")],
        )
        def update_dashboard(n):
            stats = self.collector.get_stats()

            if stats.total == 0:
                return self._empty_state()

            return (
                f"{stats.total:,}",
                f"{stats.mean:.1f} µs",
                f"{stats.p99:.1f} µs",
                self._create_dual_histogram(),
                self._create_log2_buckets(),
                self._create_timeseries(),
            )

    def _empty_state(self):
        """Return empty state for dashboard."""
        empty_fig = go.Figure()
        empty_fig.update_layout(
            title="Waiting for data... Generate some disk I/O!", template="plotly_white"
        )
        # ✅ Return 6 values (3 stats + 3 figures)
        return "0", "0 µs", "0 µs", empty_fig, empty_fig, empty_fig

    def _create_dual_histogram(self) -> go.Figure:
        """Create side-by-side linear and log2 histograms."""
        latencies = self.collector.get_all_latencies()

        # Create subplots
        fig = make_subplots(
            rows=1,
            cols=2,
            subplot_titles=("Linear Scale", "Log2 Scale"),
            horizontal_spacing=0.12,
        )

        # Linear histogram
        fig.add_trace(
            go.Histogram(
                x=latencies,
                nbinsx=50,
                marker_color="rgb(55, 83, 109)",
                opacity=0.75,
                name="Linear",
            ),
            row=1,
            col=1,
        )

        # Log2 histogram
        log2_latencies = np.log2(latencies + 1)  # +1 to avoid log2(0)
        fig.add_trace(
            go.Histogram(
                x=log2_latencies,
                nbinsx=30,
                marker_color="rgb(243, 156, 18)",
                opacity=0.75,
                name="Log2",
            ),
            row=1,
            col=2,
        )

        # Update axes
        fig.update_xaxes(title_text="Latency (µs)", row=1, col=1)
        fig.update_xaxes(title_text="log2(Latency in µs)", row=1, col=2)
        fig.update_yaxes(title_text="Count", row=1, col=1)
        fig.update_yaxes(title_text="Count", row=1, col=2)

        fig.update_layout(
            title_text="📊 Latency Distribution (Linear vs Log2)",
            template="plotly_white",
            showlegend=False,
            height=450,
        )

        return fig

    def _create_log2_buckets(self) -> go.Figure:
        """Create bar chart of log2 buckets (like BCC histogram)."""
        buckets = self.collector.get_histogram_buckets()

        if not buckets:
            fig = go.Figure()
            fig.update_layout(
                title="🔥 Log2 Histogram - Waiting for data...", template="plotly_white"
            )
            return fig

        # Sort buckets
        sorted_buckets = sorted(buckets.keys())
        counts = [buckets[b] for b in sorted_buckets]

        # Create labels (e.g., "8-16µs", "16-32µs")
        labels = []
        hover_text = []
        for bucket in sorted_buckets:
            lower = 2**bucket
            upper = 2 ** (bucket + 1)
            labels.append(f"{lower}-{upper}")

            # Calculate percentage
            total = sum(counts)
            pct = (buckets[bucket] / total) * 100 if total > 0 else 0
            hover_text.append(
                f"Range: {lower}-{upper} µs<br>"
                f"Count: {buckets[bucket]:,}<br>"
                f"Percentage: {pct:.2f}%"
            )

        # Create bar chart
        fig = go.Figure()

        fig.add_trace(
            go.Bar(
                x=labels,
                y=counts,
                marker=dict(
                    color=counts,
                    colorscale="YlOrRd",
                    showscale=True,
                    colorbar=dict(title="Count"),
                ),
                text=counts,
                textposition="outside",
                hovertext=hover_text,
                hoverinfo="text",
            )
        )

        fig.update_layout(
            title="🔥 Log2 Histogram (BCC-style buckets)",
            xaxis_title="Latency Range (µs)",
            yaxis_title="Count",
            template="plotly_white",
            height=350,
            xaxis=dict(tickangle=-45),
        )

        return fig

    def _create_timeseries(self) -> go.Figure:
        """Create time series figure."""
        recent = self.collector.get_recent_latencies()

        if not recent:
            fig = go.Figure()
            fig.update_layout(
                title="⏱️ Real-time Latency - Waiting for data...",
                template="plotly_white",
            )
            return fig

        times = [d["time"] for d in recent]
        lats = [d["latency"] for d in recent]

        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=times,
                y=lats,
                mode="lines",
                line=dict(color="rgb(231, 76, 60)", width=2),
                fill="tozeroy",
                fillcolor="rgba(231, 76, 60, 0.2)",
            )
        )

        fig.update_layout(
            title="⏱️ Real-time Latency (Last 10,000 samples)",
            xaxis_title="Time (seconds)",
            yaxis_title="Latency (µs)",
            template="plotly_white",
            height=300,
        )

        return fig

    def run(self, host: str = "0.0.0.0", port: int = 8050, debug: bool = False):
        """Run the dashboard server."""
        print(f"\n{'=' * 60}")
        print(f"🚀 Dashboard running at: http://{host}:{port}")
        print("   Access from your browser to see live graphs")
        print(
            "   Generate disk I/O to see data: dd if=/dev/zero of=/tmp/test bs=1M count=100"
        )
        print(f"{'=' * 60}\n")
        self.app.run(debug=debug, host=host, port=port)
