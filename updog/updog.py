"""Entrypoint for the module."""

# standard imports
import io
import json
import logging
import os
import pathlib
import typing

# thirdparty imports
import pyshark

# project imports
from updog.plugin_base import BasePlugin
from updog.plugins.Connections import ConnectionPlugin
from updog.plugins.DNS import DNSPlugin
from updog.plugins.HTTP import HTTPPlugin
from updog.plugins.Layer3Protocols import Layer3ProtocolPlugin
from updog.plugins.Protocols import ProtocolPlugin
from updog.plugins.Summary import SummaryPlugin

logger = logging.getLogger(__name__)

# plugins to analyse PCAP with
PLUGINS: list[typing.Callable[[], BasePlugin]] = [
    SummaryPlugin,
    ProtocolPlugin,
    ConnectionPlugin,
    Layer3ProtocolPlugin,
    DNSPlugin,
    HTTPPlugin,
]

TEMPLATE_HTML_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "assets",
    "index.html",
)


def process_html(html_data: dict) -> str:
    """Insert plugin data into html template."""
    with open(TEMPLATE_HTML_PATH) as fp:
        out = fp.read()

    # add tab headers
    tab_headers = ""

    for i, plugin in enumerate(html_data):
        css_class = f"{'active ' if i == 0 else ''}item"
        tab_headers += f'<div class="{css_class}" data-tab="{plugin}">{plugin}</div>\n'

    # add tabs
    tabs = ""
    for i, kv in enumerate(html_data.items()):
        plugin, html = kv
        css_class = f"ui bottom attached {'active ' if i == 0 else ''}tab segment"
        tabs += f'<div class="{css_class}" data-tab="{plugin}">{html}</div>\n'

    out = out.replace("{{ tab headers }}", tab_headers)
    return out.replace("{{ tabs }}", tabs)


def analyse(
    pcap_path: pathlib.Path,
    json_out: io.TextIOBase,
    html_out: io.TextIOBase,
) -> None:
    """Analyse a pcap and output to the specified files."""
    json_data = {}
    html_data = {}
    instantiated_plugins = []

    for plugin_class in PLUGINS:
        plugin = plugin_class()
        instantiated_plugins.append(plugin)

        logger.info(f"instantiated {plugin.name()} plugin")

    pcap = pyshark.FileCapture(pcap_path, keep_packets=False)

    # cheating for Summary plugin to get filepath
    SummaryPlugin.pcap_filepath = pcap_path

    for i, packet in enumerate(pcap):
        if i % 1000 == 0:
            logger.info(f"analysing packet: {i}")

        for plugin in instantiated_plugins:
            plugin.analyse_packet(packet)

    logger.info("finalising analysis")
    for plugin in instantiated_plugins:
        analysis_data = plugin.analyse_end()
        json_data[plugin.name()] = analysis_data
        html_data[plugin.name()] = plugin.visualise(analysis_data)

    logger.info("closing pcap")
    pcap.close()

    json.dump(json_data, json_out, indent=4)
    logger.info(f"wrote JSON output to {json_out.name}")  # type: ignore

    if html_out:
        html = process_html(html_data)
        html_out.write(html)
        logger.info(f"wrote html output to {html_out.name}")  # type: ignore
