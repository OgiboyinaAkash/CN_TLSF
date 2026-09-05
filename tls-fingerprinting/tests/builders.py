"""Helpers to hand-build synthetic raw TLS ClientHello records for tests,
so parsing/fingerprinting logic can be verified without needing a live
network capture or a fixture pcap file.
"""


def _u16(n):
    return n.to_bytes(2, "big")


def _u24(n):
    return n.to_bytes(3, "big")


def build_client_hello_record(
    version=0x0303,
    ciphers=(0x1301, 0x1302, 0x0A0A),
    groups=(0x001D, 0x0017, 0x0A0A),
    point_formats=(0,),
    sni=None,
):
    body = _u16(version) + b"\x00" * 32  # client_version + random
    body += bytes([0])  # session_id length = 0

    cs_bytes = b"".join(_u16(c) for c in ciphers)
    body += _u16(len(cs_bytes)) + cs_bytes

    body += bytes([1, 0])  # compression_methods: length 1, method "null"

    ext_bytes = b""
    if sni:
        name = sni.encode()
        sni_entry = bytes([0]) + _u16(len(name)) + name
        sni_ext_data = _u16(len(sni_entry)) + sni_entry
        ext_bytes += _u16(0x0000) + _u16(len(sni_ext_data)) + sni_ext_data

    groups_bytes = b"".join(_u16(g) for g in groups)
    sg_data = _u16(len(groups_bytes)) + groups_bytes
    ext_bytes += _u16(0x000A) + _u16(len(sg_data)) + sg_data

    pf_data = bytes([len(point_formats)]) + bytes(point_formats)
    ext_bytes += _u16(0x000B) + _u16(len(pf_data)) + pf_data

    body += _u16(len(ext_bytes)) + ext_bytes

    handshake = bytes([1]) + _u24(len(body)) + body
    record = bytes([22]) + _u16(0x0301) + _u16(len(handshake)) + handshake
    return record
