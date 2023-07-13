# UPDOG

Understanding PCAPs with Data Or Graphs

UPDOG is a tool for getting a high level overview of a PCAP, to draw attention
to potential areas of interest.

## What's UPDOG?

Not much, how about you?

## Quick start

```sh
python3 -m venv venv
. ./venv/bin/activate
pip3 install -r requirements.txt
sudo apt install tshark
pre-commit install
```

## Example output

### HTTP.cap

Example output generated using the HTTP.cap example pcap from
https://wiki.wireshark.org/SampleCaptures.

#### Summary page

![Summary page](./images/http_cap_summary.png)

#### Connections graph

![Connections graph](./images/http_cap_connections.png)
#### HTTP table

![HTTP table](./images/http_cap_http.png)

### ultimate_wireshark_protocols_pcap_220213.pcap

Example output generated using a subset of the
ultimate_wireshark_protocols_pcap_220213.pcap example pcap from
https://wiki.wireshark.org/SampleCaptures.

#### Protocols graph

![Protocols graph](./images/ultimate_pcap_protocols.png)

#### DNS table

![DNS table](./images/ultimate_pcap_dns.png)
