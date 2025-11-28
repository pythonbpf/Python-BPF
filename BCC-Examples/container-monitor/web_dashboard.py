"""Beautiful web dashboard for container monitoring using Plotly Dash."""

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Optional
from data_collection import ContainerDataCollector
import sys


class WebDashboard:
    """Beautiful web dashboard for container monitoring."""

    def __init__(self, collector: ContainerDataCollector,
                 selected_cgroup: Optional[int] = None,
                 host: str = "0.0.0.0",
                 port: int = 8050):
        self.collector = collector
        self.selected_cgroup = selected_cgroup
        self.host = host
        self.port = port

        # Suppress Dash dev tools and debug output
        self.app = dash.Dash(
            __name__,
            title="Container Monitor",
            suppress_callback_exceptions=True
        )

        self._setup_layout()
        self._setup_callbacks()
        self._running = False

    def _setup_layout(self):
        """Create the dashboard layout."""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1(
                    "🐳 Container Monitor Dashboard",
                    style={
                        'textAlign': 'center',
                        'color': '#ffffff',
                        'marginBottom': '10px',
                        'fontSize': '48px',
                        'fontWeight': 'bold',
                        'textShadow': '2px 2px 4px rgba(0,0,0,0.3)'
                    }
                ),
                html.Div(
                    id='cgroup-name',
                    style={
                        'textAlign': 'center',
                        'color': '#e0e0e0',
                        'fontSize': '24px',
                        'marginBottom': '20px'
                    }
                )
            ], style={
                'background': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                'padding': '30px',
                'borderRadius': '10px',
                'marginBottom': '20px',
                'boxShadow': '0 10px 30px rgba(0,0,0,0.3)'
            }),

            # Cgroup selector (if no cgroup selected)
            html.Div([
                html.Label("Select Cgroup:", style={
                    'fontSize': '18px',
                    'fontWeight': 'bold',
                    'color': '#333',
                    'marginRight': '10px'
                }),
                dcc.Dropdown(
                    id='cgroup-selector',
                    style={'width': '500px', 'display': 'inline-block'}
                )
            ], id='selector-container', style={
                'textAlign': 'center',
                'marginBottom': '30px',
                'display': 'block' if self.selected_cgroup is None else 'none'
            }),

            # Stats cards row
            html.Div([
                self._create_stat_card('syscall-card', '⚡ Syscalls', '#8b5cf6'),
                self._create_stat_card('network-card', '🌐 Network Traffic', '#3b82f6'),
                self._create_stat_card('file-card', '💾 File I/O', '#ef4444'),
            ], style={
                'display': 'flex',
                'justifyContent': 'space-around',
                'marginBottom': '30px',
                'gap': '20px',
                'flexWrap': 'wrap'
            }),

            # Graphs container
            html.Div([
                # Network graphs
                html.Div([
                    html.H2("🌐 Network I/O", style={
                        'color': '#3b82f6',
                        'borderBottom': '3px solid #3b82f6',
                        'paddingBottom': '10px',
                        'marginBottom': '20px'
                    }),
                    dcc.Graph(id='network-graph', style={'height': '400px'}),
                ], style={
                    'background': 'white',
                    'padding': '25px',
                    'borderRadius': '10px',
                    'boxShadow': '0 4px 15px rgba(0,0,0,0.1)',
                    'marginBottom': '30px'
                }),

                # File I/O graphs
                html.Div([
                    html.H2("💾 File I/O", style={
                        'color': '#ef4444',
                        'borderBottom': '3px solid #ef4444',
                        'paddingBottom': '10px',
                        'marginBottom': '20px'
                    }),
                    dcc.Graph(id='file-io-graph', style={'height': '400px'}),
                ], style={
                    'background': 'white',
                    'padding': '25px',
                    'borderRadius': '10px',
                    'boxShadow': '0 4px 15px rgba(0,0,0,0.1)',
                    'marginBottom': '30px'
                }),

                # Combined time series
                html.Div([
                    html.H2("📈 Real-time Metrics", style={
                        'color': '#10b981',
                        'borderBottom': '3px solid #10b981',
                        'paddingBottom': '10px',
                        'marginBottom': '20px'
                    }),
                    dcc.Graph(id='timeseries-graph', style={'height': '500px'}),
                ], style={
                    'background': 'white',
                    'padding': '25px',
                    'borderRadius': '10px',
                    'boxShadow': '0 4px 15px rgba(0,0,0,0.1)'
                }),
            ]),

            # Auto-update interval
            dcc.Interval(id='interval-component', interval=1000, n_intervals=0),

        ], style={
            'padding': '20px',
            'fontFamily': "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
            'background': '#f3f4f6',
            'minHeight': '100vh'
        })

    def _create_stat_card(self, card_id: str, title: str, color: str):
        """Create a statistics card."""
        return html.Div([
            html.H3(title, style={
                'color': color,
                'fontSize': '20px',
                'marginBottom': '15px',
                'fontWeight': 'bold'
            }),
            html.Div([
                html.Div(id=f'{card_id}-value', style={
                    'fontSize': '36px',
                    'fontWeight': 'bold',
                    'color': '#1f2937',
                    'marginBottom': '5px'
                }),
                html.Div(id=f'{card_id}-rate', style={
                    'fontSize': '16px',
                    'color': '#6b7280'
                })
            ])
        ], style={
            'flex': '1',
            'minWidth': '250px',
            'background': 'white',
            'padding': '25px',
            'borderRadius': '10px',
            'boxShadow': '0 4px 15px rgba(0,0,0,0.1)',
            'borderLeft': f'5px solid {color}',
            'transition': 'transform 0.2s'
        })

    def _setup_callbacks(self):
        """Setup dashboard callbacks."""

        @self.app.callback(
            [Output('cgroup-selector', 'options'),
             Output('cgroup-selector', 'value')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_cgroup_selector(n):
            if self.selected_cgroup is not None:
                return [], self.selected_cgroup

            cgroups = self.collector.get_all_cgroups()
            options = [{'label': f"{cg.name} (ID: {cg.id})", 'value': cg.id}
                       for cg in sorted(cgroups, key=lambda c: c.name)]
            value = options[0]['value'] if options else None

            if value and self.selected_cgroup is None:
                self.selected_cgroup = value

            return options, self.selected_cgroup

        @self.app.callback(
            Output('cgroup-selector', 'value', allow_duplicate=True),
            [Input('cgroup-selector', 'value')],
            prevent_initial_call=True
        )
        def select_cgroup(value):
            if value:
                self.selected_cgroup = value
            return value

        @self.app.callback(
            [
                Output('cgroup-name', 'children'),
                Output('syscall-card-value', 'children'),
                Output('syscall-card-rate', 'children'),
                Output('network-card-value', 'children'),
                Output('network-card-rate', 'children'),
                Output('file-card-value', 'children'),
                Output('file-card-rate', 'children'),
                Output('network-graph', 'figure'),
                Output('file-io-graph', 'figure'),
                Output('timeseries-graph', 'figure'),
            ],
            [Input('interval-component', 'n_intervals')]
        )
        def update_dashboard(n):
            if self.selected_cgroup is None:
                empty_fig = go.Figure()
                empty_fig.update_layout(
                    title="Select a cgroup to begin monitoring",
                    template="plotly_white"
                )
                return ("Select a cgroup", "0", "", "0 B", "", "0 B", "", empty_fig, empty_fig, empty_fig)

            try:
                stats = self.collector.get_stats_for_cgroup(self.selected_cgroup)
                history = self.collector.get_history(self.selected_cgroup)
                rates = self._calculate_rates(history)

                return (
                    f"Monitoring: {stats.cgroup_name}",
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
                empty_fig = go.Figure()
                empty_fig.update_layout(title=f"Error: {str(e)}", template="plotly_white")
                return ("Error", "0", str(e), "0 B", "", "0 B", "", empty_fig, empty_fig, empty_fig)

    def _create_network_graph(self, history):
        """Create network I/O graph."""
        if len(history) < 2:
            fig = go.Figure()
            fig.update_layout(title="Collecting data...", template="plotly_white")
            return fig

        times = [i for i in range(len(history))]
        rx_bytes = [s.rx_bytes for s in history]
        tx_bytes = [s.tx_bytes for s in history]

        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=("Received (RX)", "Transmitted (TX)"),
            vertical_spacing=0.15
        )

        fig.add_trace(
            go.Scatter(
                x=times, y=rx_bytes,
                mode='lines',
                name='RX',
                fill='tozeroy',
                line=dict(color='#3b82f6', width=3),
                fillcolor='rgba(59, 130, 246, 0.2)'
            ),
            row=1, col=1
        )

        fig.add_trace(
            go.Scatter(
                x=times, y=tx_bytes,
                mode='lines',
                name='TX',
                fill='tozeroy',
                line=dict(color='#fbbf24', width=3),
                fillcolor='rgba(251, 191, 36, 0.2)'
            ),
            row=2, col=1
        )

        fig.update_xaxes(title_text="Time (samples)", row=2, col=1)
        fig.update_yaxes(title_text="Bytes", row=1, col=1)
        fig.update_yaxes(title_text="Bytes", row=2, col=1)

        fig.update_layout(
            height=400,
            template="plotly_white",
            showlegend=False,
            hovermode='x unified'
        )

        return fig

    def _create_file_io_graph(self, history):
        """Create file I/O graph."""
        if len(history) < 2:
            fig = go.Figure()
            fig.update_layout(title="Collecting data...", template="plotly_white")
            return fig

        times = [i for i in range(len(history))]
        read_bytes = [s.read_bytes for s in history]
        write_bytes = [s.write_bytes for s in history]

        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=("Read Operations", "Write Operations"),
            vertical_spacing=0.15
        )

        fig.add_trace(
            go.Scatter(
                x=times, y=read_bytes,
                mode='lines',
                name='Read',
                fill='tozeroy',
                line=dict(color='#ef4444', width=3),
                fillcolor='rgba(239, 68, 68, 0.2)'
            ),
            row=1, col=1
        )

        fig.add_trace(
            go.Scatter(
                x=times, y=write_bytes,
                mode='lines',
                name='Write',
                fill='tozeroy',
                line=dict(color='#8b5cf6', width=3),
                fillcolor='rgba(139, 92, 246, 0.2)'
            ),
            row=2, col=1
        )

        fig.update_xaxes(title_text="Time (samples)", row=2, col=1)
        fig.update_yaxes(title_text="Bytes", row=1, col=1)
        fig.update_yaxes(title_text="Bytes", row=2, col=1)

        fig.update_layout(
            height=400,
            template="plotly_white",
            showlegend=False,
            hovermode='x unified'
        )

        return fig

    def _create_timeseries_graph(self, history):
        """Create combined time series graph."""
        if len(history) < 2:
            fig = go.Figure()
            fig.update_layout(title="Collecting data...", template="plotly_white")
            return fig

        times = [i for i in range(len(history))]

        fig = make_subplots(
            rows=3, cols=1,
            subplot_titles=("System Calls", "Network Traffic (Bytes)", "File I/O (Bytes)"),
            vertical_spacing=0.1,
            specs=[[{"secondary_y": False}], [{"secondary_y": True}], [{"secondary_y": True}]]
        )

        # Syscalls
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.syscall_count for s in history],
                mode='lines',
                name='Syscalls',
                line=dict(color='#8b5cf6', width=2)
            ),
            row=1, col=1
        )

        # Network
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.rx_bytes for s in history],
                mode='lines',
                name='RX',
                line=dict(color='#3b82f6', width=2)
            ),
            row=2, col=1, secondary_y=False
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.tx_bytes for s in history],
                mode='lines',
                name='TX',
                line=dict(color='#fbbf24', width=2)
            ),
            row=2, col=1, secondary_y=True
        )

        # File I/O
        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.read_bytes for s in history],
                mode='lines',
                name='Read',
                line=dict(color='#ef4444', width=2)
            ),
            row=3, col=1, secondary_y=False
        )

        fig.add_trace(
            go.Scatter(
                x=times,
                y=[s.write_bytes for s in history],
                mode='lines',
                name='Write',
                line=dict(color='#8b5cf6', width=2)
            ),
            row=3, col=1, secondary_y=True
        )

        fig.update_xaxes(title_text="Time (samples)", row=3, col=1)
        fig.update_yaxes(title_text="Count", row=1, col=1)
        fig.update_yaxes(title_text="RX Bytes", row=2, col=1, secondary_y=False)
        fig.update_yaxes(title_text="TX Bytes", row=2, col=1, secondary_y=True)
        fig.update_yaxes(title_text="Read Bytes", row=3, col=1, secondary_y=False)
        fig.update_yaxes(title_text="Write Bytes", row=3, col=1, secondary_y=True)

        fig.update_layout(
            height=500,
            template="plotly_white",
            hovermode='x unified',
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )

        return fig

    def _calculate_rates(self, history):
        """Calculate rates from history."""
        if len(history) < 2:
            return {
                'syscalls_per_sec': 0.0,
            'rx_bytes_per_sec': 0.0,
            'tx_bytes_per_sec': 0.0,
            'read_bytes_per_sec': 0.0,
            'write_bytes_per_sec': 0.0,
            }

        recent = history[-1]
        previous = history[-2]
        time_delta = recent.timestamp - previous.timestamp

        if time_delta <= 0:
            time_delta = 1.0

        return {
            'syscalls_per_sec': max(0, (recent.syscall_count - previous.syscall_count) / time_delta),
            'rx_bytes_per_sec': max(0, (recent.rx_bytes - previous.rx_bytes) / time_delta),
            'tx_bytes_per_sec': max(0, (recent.tx_bytes - previous.tx_bytes) / time_delta),
            'read_bytes_per_sec': max(0, (recent.read_bytes - previous.read_bytes) / time_delta),
            'write_bytes_per_sec': max(0, (recent.write_bytes - previous.write_bytes) / time_delta),
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
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        self.app.run(
            debug=False,
            host=self.host,
            port=self.port,
            use_reloader=False
        )

    def stop(self):
        """Stop the web dashboard."""
        self._running = False
