"""Live sniffing and pcap replay, with per-flow TCP reassembly so that a
ClientHello/ServerHello split across multiple TCP segments still parses.

Assumes in-order packet delivery (true for the vast majority of local
captures); out-of-order segments are simply appended in arrival order, which
is an accepted simplification for a fingerprinting demo tool.
"""
from scapy.all import sniff, rdpcap, IP, IPv6, TCP, Raw

from .tls_parser import try_extract_handshakes, CLIENT_HELLO, SERVER_HELLO


class FlowBuffer:
    def __init__(self, max_bytes: int = 65536):
        self.data = bytearray()
        self.max_bytes = max_bytes
        self.done = False

    def feed(self, payload: bytes):
        if self.done:
            return None
        self.data += payload
        if len(self.data) > self.max_bytes:
            self.done = True  # handshake never resolved within a sane window; give up
            return None
        found = try_extract_handshakes(bytes(self.data))
        if found:
            self.done = True
        return found or None


class HandshakeCollector:
    """Feeds packets into per-(src,sport,dst,dport) buffers and fires
    callbacks as soon as a ClientHello/ServerHello can be parsed out.
    """

    def __init__(self, on_client_hello=None, on_server_hello=None):
        self.buffers = {}
        self.on_client_hello = on_client_hello
        self.on_server_hello = on_server_hello

    def handle_packet(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return

        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        key = (src, sport, dst, dport)
        buf = self.buffers.setdefault(key, FlowBuffer())
        found = buf.feed(bytes(pkt[Raw].load))
        if not found:
            return
        if CLIENT_HELLO in found and self.on_client_hello:
            self.on_client_hello(found[CLIENT_HELLO], key)
        if SERVER_HELLO in found and self.on_server_hello:
            self.on_server_hello(found[SERVER_HELLO], key)


def live_capture(
    iface=None,
    bpf_filter="tcp",
    duration=None,
    packet_count=None,
    on_client_hello=None,
    on_server_hello=None,
):
    collector = HandshakeCollector(on_client_hello, on_server_hello)
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=collector.handle_packet,
        store=False,
        timeout=duration,
        count=packet_count or 0,
    )


def read_pcap(path, on_client_hello=None, on_server_hello=None):
    collector = HandshakeCollector(on_client_hello, on_server_hello)
    for pkt in rdpcap(path):
        collector.handle_packet(pkt)
