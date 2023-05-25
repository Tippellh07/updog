"""Plugin for getting connection information."""

# standard imports
import json
import typing

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = r"""
    <script>
        function clear_overview() {
            const myNode = document.getElementById('connections_graph');
            while (myNode.firstChild) {
                myNode.removeChild(myNode.firstChild);
            }
        }

        function draw_overview(hosts, connections) {
            // Remove any old overviews
            clear_overview();

            // Setup svg
            const width = document.getElementsByClassName(
                'ui bottom attached active tab segment')[0].offsetWidth;
            const height = Math.max(
                document.getElementsByClassName(
                    'ui bottom attached active tab segment')[0].offsetHeight,
                500);
            const icon_url = 'https://encrypted-tbn0.gstatic.com/images?' +
                'q=tbn:ANd9GcRxPzUJXCQMLU5bFWl26g7AJFYbtTjhVGmJLg&usqp=CAU';

            const svg = d3.select('.overview').append('svg')
                .attr('width', width)
                .attr('height', height);

            const force = d3.layout.force()
                .gravity(0.05)
                .distance(100)
                .charge(-100)
                .size([width, height]);

            let all_nodes = [];
            let all_links = [];
            let node_ids = {};

            // Add nodes for hosts
            hosts.forEach(function (host, index) {
                all_nodes.push({
                    'name': host,
                    'x': (width / hosts.length),
                    'y': height / 2,
                    'id': index
                });
                node_ids[host] = index;
            });

            // add links for connections
            for (let src of Object.keys(connections))
            {
                connections[src].forEach(function (dest) {
                    all_links.push({
                        'source': node_ids[src],
                        'target': node_ids[dest],
                        'value': 1
                    });
                })
            }

            force.nodes(all_nodes)
                .links(all_links)
                .start();

            const link = svg.selectAll('.link')
                .data(all_links)
                .enter().append('line')
                .attr('class', 'link');

            const node = svg.selectAll('.node')
                .data(all_nodes)
                .enter().append('g')
                .attr('class', 'node')
                .call(force.drag);

            node.append('image')
                .attr('xlink:href', icon_url)
                .attr('x', -8)
                .attr('y', -8)
                .attr('width', 16)
                .attr('height', 16);

            node.append('text')
                .attr('dx', 12)
                .attr('dy', '.35em')
                .attr('fill', 'white')
                .text(d => d.name );

            force.on('tick', function() {
                link.attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);

                node.attr('transform', d => `translate(${d.x}, ${d.y})`);
            });
        }

        $(document).ready(function () {
            const data = {{ data }};

            draw_overview(data.hosts, data.connections);

        });
    </script>

    <div id="connections_graph" class="overview">
    </div>
"""


class ConnectionPlugin(BasePlugin):
    """Plugin for getting connection information."""

    def name(self) -> str:
        """Name of the plugin."""
        return "Connections (ipv4)"

    def __init__(self) -> None:
        """Initialise data for the plugin."""
        self.hosts: set[str] = set()
        self.connections: dict[str, set] = {}

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Get the connections from the packet."""
        if hasattr(packet, "ip"):
            self.hosts.add(packet.ip.src_host)
            self.hosts.add(packet.ip.dst_host)
            if packet.ip.src_host not in self.connections:
                self.connections[packet.ip.src_host] = set()
            self.connections[packet.ip.src_host].add(
                packet.ip.dst_host,
            )

    def analyse_end(self) -> dict:
        """cast connection and host sets to lists to allow json serialisation."""
        data: dict[typing.Any, typing.Any] = {"connections": {}}
        for key in self.connections:
            data["connections"][key] = list(self.connections[key])
        data["hosts"] = list(self.hosts)

        return data

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the connections with a force directed graph."""
        return HTML_TEMPLATE.replace("{{ data }}", json.dumps(analysis_data))
