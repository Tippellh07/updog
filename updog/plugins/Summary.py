"""Plugin for getting number of each highest layer protocol."""

# standard imports
import datetime
import os
import pathlib

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin

HTML_TEMPLATE = """
    <div>
        <div class="ui statistic">
            <div class="label">
                File name
            </div>
            <div class="value" style="text-transform: none;">
                {file_name}
            </div>
        </div>
        <br/>
        <div class="ui statistic">
            <div class="label">
                Start time
            </div>
            <div class="value">
                {start_time}
            </div>
        </div>
        <br/>
        <div class="ui statistic">
            <div class="label">
                Captured time (seconds)
            </div>
            <div class="value">
                {time_of_capture}
            </div>
        </div>
        <br/>
        <div class="ui statistic">
            <div class="label">
                Number of packets
            </div>
            <div class="value">
                {number_of_packets}
            </div>
        </div>
    </div>
"""


class SummaryPlugin(BasePlugin):
    """Plugin for getting number of each highest layer protocol."""

    pcap_filepath: pathlib.Path = None

    def __init__(self) -> None:
        """Overridden initialisor to keep file name."""
        self.n_packets = 0
        self.packet_0: pyshark.packet.packet.Packet = None
        self.last_packet: pyshark.packet.packet.Packet = None

    def name(self) -> str:
        """Name of the plugin."""
        return "Summary"

    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Iterate over all packets to allow accessing first and last packets."""
        if self.packet_0 is None:
            self.packet_0 = packet
        self.last_packet = packet

    def analyse_end(self) -> dict:
        """Get a summary of the pcap as a whole."""
        start_time = datetime.datetime.fromtimestamp(
            float(self.packet_0.frame_info.time_epoch),
        )

        return {
            "file_name": os.path.basename(self.pcap_filepath),
            "start_time": start_time.isoformat(),
            "number_of_packets": self.last_packet.frame_info.number,
            "time_of_capture": round(
                float(self.last_packet.frame_info.time_relative),
                2,
            ),
        }

    def visualise(self, analysis_data: dict) -> str:
        """Visualise the summary with statistics."""
        return HTML_TEMPLATE.format(**analysis_data)
