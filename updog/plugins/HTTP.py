"""Plugin for getting summary of HTTP packets."""

# standard imports
import datetime
import json

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <script>
        $(document).ready(function () {
            $('#HTTP_request_table').DataTable();
            $('#HTTP_request_by_path_table').DataTable();

            // Draw chart
            const data = {{ method_data }};

            Plotly.newPlot(
                'http-method-chart',
                [{
                    'labels': Object.keys(data),
                    'values': Object.values(data),
                    'type': 'pie'
                }],
                plotly_style);

            // Resize chart when necessary
            addEventListener(
                "resize",
                () => { resize_plotly_chart('http-method-chart') }
            );
        });
    </script>
    <div class="container centered">
        <!-- Tab headers -->
        <div class="ui top attached tabular menu">
            <div class="active item" data-tab="http-requests">Requests</div>
            <div class="item" data-tab="http-method-summary">
                Request Methods Summary
            </div>
            <div class="item" data-tab="http-requests-by-url">Requests By URL</div>
        </div>

        <!-- Tabs -->
        <div class="ui bottom attached active tab segment" data-tab="http-requests">
            <table id="HTTP_request_table" class="display">
                {{ request_data }}
            </table>
        </div>
        <div class="ui bottom attached tab segment" data-tab="http-method-summary">
            <div id="http-method-chart" class="centered">
            </div>
        </div>
        <div class="ui bottom attached tab segment" data-tab="http-requests-by-url">
            <table id="HTTP_request_by_path_table" class="display">
                {{ request_by_path_data }}
            </table>
        </div>
    </div>
"""


class HTTPPlugin(BasePlugin):
    """Plugin for getting summary of HTTP packets."""

    def __init__(self) -> None:
        """Initialise plugin data."""
        self.http_requests: list[dict[str, str]] = []
        self.http_methods: dict[str, int] = {}
        self.http_requests_by_path: dict[str, dict] = {}

    def name(self) -> str:
        """Name of the plugin."""
        return "HTTP"

    def _update_request_summary(
        self,
        packet: pyshark.packet.packet.Packet,
    ) -> None:
        self.http_requests.append(
            {
                "time": datetime.datetime.fromtimestamp(
                    float(packet.frame_info.time_epoch),
                ).isoformat(),
                "url": packet.http.request_full_uri,
                "method": packet.http.request_method,
                "referer": getattr(packet.http, "referer", ""),
            },
        )

    def _update_request_paths(self, packet: pyshark.packet.packet.Packet) -> None:
        full_uri = packet.http.request_full_uri
        if full_uri not in self.http_requests_by_path:
            self.http_requests_by_path[full_uri] = {
                "count": 0,
                "methods": set(),
            }
        self.http_requests_by_path[full_uri]["count"] += 1
        self.http_requests_by_path[full_uri]["methods"].add(
            packet.http.request_method,
        )

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Analyse DNS packet information."""
        if not hasattr(packet, "http"):
            return

        if hasattr(packet.http, "request_full_uri"):
            self._update_request_summary(packet)
            self._update_request_paths(packet)
            if packet.http.request_method not in self.http_methods:
                self.http_methods[packet.http.request_method] = 1
            else:
                self.http_methods[packet.http.request_method] += 1

    def analyse_end(self) -> dict:
        """Combine and return data."""
        for url in self.http_requests_by_path:
            self.http_requests_by_path[url]["methods"] = list(
                self.http_requests_by_path[url]["methods"],
            )

        return {
            "http_requests": self.http_requests,
            "http_method_summary": self.http_methods,
            "http_requests_by_path": self.http_requests_by_path,
        }

    def to_request_table_data(self, analysis_data: list) -> str:
        """Convert HTTP requests to HTML table."""
        all_fields = [
            "time",
            "url",
            "method",
            "referer",
        ]

        out = (
            "<thead><tr>"
            + "".join([f"<th>{name.capitalize()}</th>" for name in all_fields])
            + "</tr></thead>\n<tbody>\n"
        )

        for packet in analysis_data:
            out += (
                "<tr>"
                + "".join([f"<td>{packet[name]}</td>" for name in all_fields])
                + "</tr>\n"
            )

        return out + "\n</tbody>"

    def to_request_by_path_table(self, analysis_data: dict) -> str:
        """Convert HTTP requests by path to table."""
        all_fields = ["URL", "Request Count", "Methods"]

        out = (
            "<thead><tr>"
            + "".join([f"<th>{name}</th>" for name in all_fields])
            + "</tr></thead>\n<tbody>\n"
        )

        for url, details in analysis_data.items():
            out += (
                f"<tr><td>{url}</td>"
                f'<td>{details["count"]}</td>'
                f'<td>{"".join(details["methods"])}</td>'
                "</tr>\n"
            )

        return out + "\n</tbody>"

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the DNS packets in a table."""
        return (
            HTML_TEMPLATE.replace(
                "{{ request_data }}",
                self.to_request_table_data(analysis_data["http_requests"]),
            )
            .replace(
                "{{ request_by_path_data }}",
                self.to_request_by_path_table(analysis_data["http_requests_by_path"]),
            )
            .replace(
                "{{ method_data }}",
                json.dumps(analysis_data["http_method_summary"]),
            )
        )
