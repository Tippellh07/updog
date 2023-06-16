"""Plugin for getting summary of overall traffic."""

# standard imports
import json

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <script>
        function make_traffic_bar_chart(div)
        {
            const up_data_raw = {{ up_data_raw }};
            const up_data = {
                'x': Object.keys(up_data_raw),
                'y': Object.values(up_data_raw),
                'name': 'up',
                'type': 'bar'
            };
            const down_data_raw = {{ down_data_raw }};
            const down_data = {
                'x': Object.keys(down_data_raw),
                'y': Object.values(down_data_raw),
                'name': 'down',
                'type': 'bar'
            };

            const layout = {
                ...plotly_style,
                'width': up_data.x.length * 50,  // fixed width bars
                'showlegend': false,
                'xaxis': {
                    'showticklabels': false
                },
                'yaxis': {
                    'title': {
                        'text': 'Bytes sent'
                    }
                }
            }

            Plotly.newPlot(
                div,
                [up_data, down_data],
                layout);
        }

        $(document).ready(function () {
            // Don't resize chart as we want to maintain a minimum bar width

            make_traffic_bar_chart('traffic_chart');
        });
    </script>
    <div id="traffic_chart" style="overflow:auto;">
    </div>
"""


class TrafficPlugin(BasePlugin):
    """Plugin for getting summary of overall traffic."""

    def __init__(self) -> None:
        """Initialise the plugin."""
        # dictionary of each connection (ip pairing) containing a sub dictionary
        # with the number of bytes sent in each direction
        # e.g. {
        #           "192.168.0.1: 10.0.0.1": {
        self.traffic_data: dict[str, dict[str, int]] = {}

    def name(self) -> str:
        """Name of the plugin."""
        return "Traffic"

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Analyse traffic sent."""
        if hasattr(packet, "ip"):
            src_dst = f"{packet.ip.src_host}: {packet.ip.dst_host}"
            dst_src = f"{packet.ip.dst_host}: {packet.ip.src_host}"

            key_in_use = src_dst

            if src_dst not in self.traffic_data and dst_src not in self.traffic_data:
                self.traffic_data[src_dst] = {
                    "up": 0,
                    "down": 0,
                }
            elif src_dst not in self.traffic_data:
                key_in_use = dst_src

            self.traffic_data[key_in_use][
                "up" if key_in_use == src_dst else "down"
            ] += int(
                packet.frame_info.len,
            )

    def analyse_end(self) -> dict:
        """Return analysed data."""
        return self.traffic_data

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the DNS packets in a table."""
        up_data = {}
        down_data = {}
        sorted_keys = sorted(
            analysis_data,
            key=lambda x: analysis_data[x]["up"] + analysis_data[x]["down"],
            reverse=True,
        )

        for key in sorted_keys:
            up_data[key.replace(": ", "<br>")] = analysis_data[key]["up"]
            down_data[key.replace(": ", "<br>")] = analysis_data[key]["down"]

        return HTML_TEMPLATE.replace("{{ up_data_raw }}", json.dumps(up_data)).replace(
            "{{ down_data_raw }}",
            json.dumps(down_data),
        )
