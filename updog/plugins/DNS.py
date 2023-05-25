"""Plugin for getting summary of DNS packets."""

# standard imports
import datetime
import typing

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <script>
        $(document).ready(function () {
            $('#DNS_ips_table').DataTable();
            $('#DNS_table').DataTable();
        });
    </script>
    <div class="container centered">
        <!-- Tab headers -->
        <div class="ui top attached tabular menu">
            <div class="active item" data-tab="dns-ips">ips</div>
            <div class="item" data-tab="dns-packet-summary">Packet Summary</div>
        </div>

        <!-- Tabs -->
        <div class="ui bottom attached active tab segment" data-tab="dns-ips">
            <table id="DNS_ips_table" class="display">
                {{ ips_data }}
            </table>
        </div>
        <div class="ui bottom attached tab segment" data-tab="dns-packet-summary">
            <table id="DNS_table" class="display">
                {{ data }}
            </table>
        </div>
    </div>
"""


class DNSPlugin(BasePlugin):
    """Plugin for getting summary of DNS packets."""

    DNS_FIELDS = ["qry_name", "qry_type", "a", "aaaa", "cname", "resp_name"]
    DNS_IP_FIELDS = ["a", "aaaa"]
    QRY_TYPE_MAP = {1: "A", 5: "CNAME", 28: "AAAA"}

    def __init__(self) -> None:
        """Initialise the plugin data."""
        self.dns_packets: list[dict[str, object]] = []
        self.ips: dict[str, dict[str, set[str]]] = {}

    def name(self) -> str:
        """Name of the plugin."""
        return "DNS"

    def _get_summary(
        self,
        packet: pyshark.packet.packet.Packet,
    ) -> dict[str, typing.Any]:
        entry = {
            "time": datetime.datetime.fromtimestamp(
                float(packet.frame_info.time_epoch),
            ).isoformat(),
        }
        for field in self.DNS_FIELDS:
            if field == "qry_type":
                qry_type = int(getattr(packet.dns, field, None))
                entry[field] = str(qry_type)
                if qry_type in self.QRY_TYPE_MAP:
                    entry[field] += f" ({self.QRY_TYPE_MAP[qry_type]})"
            else:
                entry[field] = getattr(packet.dns, field, None)

        return entry

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Analyse DNS packet information."""
        if not hasattr(packet, "dns"):
            return

        # get packet summary
        self.dns_packets.append(self._get_summary(packet))

        # get summary of resolved ips
        if hasattr(packet.dns, "resp_name"):
            if (hasattr(packet.dns, "a") or hasattr(packet.dns, "aaaa")) and (
                packet.dns.resp_name not in self.ips
            ):
                self.ips[packet.dns.resp_name] = {
                    "a": set(),
                    "aaaa": set(),
                }

            for field in self.DNS_IP_FIELDS:
                if hasattr(packet.dns, field):
                    self.ips[packet.dns.resp_name][field].add(
                        getattr(packet.dns, field),
                    )

    def analyse_end(self) -> dict:
        """Cast sets to lists to allow json serialisation."""
        # cast sets to lists to allow json serialisation
        ips_out: dict[str, dict[str, list[str]]] = {}
        for key in self.ips:
            ips_out[key] = {}
            for field in self.DNS_IP_FIELDS:
                ips_out[key][field] = list(self.ips[key][field])

        return {"dns_packets": self.dns_packets, "ips": ips_out}

    def to_summary_table_data(self, analysis_data: list) -> str:
        """Convert DNS records to HTML table."""
        all_fields = self.DNS_FIELDS
        all_fields.insert(0, "time")

        out = (
            "<thead><tr>"
            + "".join([f"<th>{name}</th>" for name in all_fields])
            + "</tr></thead>\n<tbody>\n"
        )

        for packet in analysis_data:
            out += (
                "<tr>"
                + "".join([f"<td>{packet[name]}</td>" for name in all_fields])
                + "</tr>\n"
            )

        return out + "\n</tbody>"

    def to_ips_table_data(self, analysis_data: dict) -> str:
        """Convert DNS ips to HTML table."""
        all_fields = ["Hostname", "ipv4", "ipv6"]

        out = (
            "<thead><tr>"
            + "".join([f"<th>{name}</th>" for name in all_fields])
            + "</tr></thead>\n<tbody>\n"
        )

        def _ips_to_entry(ips: list) -> str:
            if len(ips) == 0:
                return ""
            if len(ips) == 1:
                return ips[0]

            return ", ".join(ips)

        for hostname, ips in analysis_data.items():
            out += (
                "<tr>"
                f"<td>{hostname}</td>"
                f'<td>{_ips_to_entry(ips["a"])}</td>'
                f'<td>{_ips_to_entry(ips["aaaa"])}</td>'
                "</tr>\n"
            )

        return out + "\n</tbody>"

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the DNS packets in a table."""
        out = HTML_TEMPLATE.replace(
            "{{ data }}",
            self.to_summary_table_data(analysis_data["dns_packets"]),
        )

        return out.replace(
            "{{ ips_data }}",
            self.to_ips_table_data(analysis_data["ips"]),
        )
