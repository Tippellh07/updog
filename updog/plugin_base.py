"""Base class for analysis plugins."""

# standard imports
import abc

# thirdparty imports
import pyshark


class BasePlugin(abc.ABC):
    """Base plugin class for analysis plugins to extend."""

    def __init__(self) -> None:
        """Initialise the plugin."""
        self.data: dict[object, object] = {}

    @abc.abstractmethod
    def name(self) -> str:
        """Get the plugin name."""
        raise NotImplementedError

    @abc.abstractmethod
    def analyse_packet(self, packet: pyshark.packet.packet.Packet) -> None:
        """Analyse a single packet the pcap."""
        _ = packet
        raise NotImplementedError

    def analyse_end(self) -> dict:
        """
        End analysis.

        Called after last packet has been analysed, used for any post processing
        and to return the analysed data.
        """
        return self.data

    @abc.abstractmethod
    def visualise(self, analysis_data: dict) -> str:
        """Visualise the analysed pcap."""
        raise NotImplementedError
