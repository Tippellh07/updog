"""Plugin for getting number of each highest layer protocol."""

# standard imports
import json

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <script>
        $(document).ready(function () {
            // Draw chart
            const data = {{ data }};

            Plotly.newPlot(
                'l3_protocol_chart',
                [{
                    'labels': Object.keys(data),
                    'values': Object.values(data),
                    'type': 'pie'
                }],
                plotly_style);

            // Resize chart when necessary
            addEventListener(
                "resize",
                () => { resize_plotly_chart('l3_protocol_chart') }
            );
        });
    </script>
    <div id="l3_protocol_chart" class="centered">
    </div>
"""


class Layer3ProtocolPlugin(BasePlugin):
    """Plugin for getting number of each layer 3 protocol."""

    def name(self) -> str:
        """Name of the plugin."""
        return "Layer 3 Protocols"

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Get the number of packets of each layer 3 protocol."""
        protocol = packet.layers[1].layer_name  # because layer 1 isn't in .layers
        if protocol in self.data:
            self.data[protocol] += 1  # type: ignore
        else:
            self.data[protocol] = 1

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the protocols in a bar chart."""
        return HTML_TEMPLATE.replace("{{ data }}", json.dumps(analysis_data))
