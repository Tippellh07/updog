"""Plugin for getting number of each highest layer protocol."""

# standard imports
import json

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <script>
        function make_bar_chart(div)
        {
            const data = {{ data }};

            Plotly.newPlot(
                div,
                [{
                    'x': Object.keys(data),
                    'y': Object.values(data),
                    'type': 'bar'
                }],
                plotly_style);
        }

        $(document).ready(function () {
            // Resize chart when necessary
            addEventListener("resize", () => { resize_plotly_chart('protocol_chart') });

            make_bar_chart('protocol_chart');
        });
    </script>
    <div id="protocol_chart">
    </div>
"""


class ProtocolPlugin(BasePlugin):
    """Plugin for getting number of each highest layer protocol."""

    def name(self) -> str:
        """Name of the plugin."""
        return "Protocols"

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Get the number of packets of each highest layer protocol."""
        protocol = packet.highest_layer

        # Note that for some protocols the highest_layer isn't necessarily what
        # you want, but working around it gets hacky fast. E.g. for HTTP
        # sometimes the highest layer will actually be the MIME type, such as JSON

        if protocol in self.data:
            self.data[protocol] += 1  # type: ignore
        else:
            self.data[protocol] = 1

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the protocols in a bar chart."""
        return HTML_TEMPLATE.replace("{{ data }}", json.dumps(analysis_data))
