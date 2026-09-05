"""Minimal, dependency-free parser for TLS Handshake ClientHello/ServerHello messages.

Works directly on raw bytes captured off the wire (record layer + handshake
layer only) rather than a full TLS stack, since JA3/JA3S/JA4 only need the
plaintext handshake fields that are always sent unencrypted.
"""
from dataclasses import dataclass, field


HANDSHAKE_CONTENT_TYPE = 22
CLIENT_HELLO = 1
SERVER_HELLO = 2

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b


@dataclass
class Extension:
    type: int
    data: bytes


@dataclass
class ClientHello:
    version: int
    cipher_suites: list
    extensions: list
    supported_groups: list = field(default_factory=list)
    ec_point_formats: list = field(default_factory=list)
    sni: str = None
    alpn: list = field(default_factory=list)
    signature_algorithms: list = field(default_factory=list)
    supported_versions: list = field(default_factory=list)


@dataclass
class ServerHello:
    version: int
    cipher_suite: int
    extensions: list


def try_extract_handshakes(buf: bytes) -> dict:
    """Scan a buffer of one or more concatenated TLS records and return
    {handshake_type: body_bytes} for every *complete* ClientHello/ServerHello
    message found. Incomplete trailing records are simply left unread; feed
    more bytes and call again.
    """
    found = {}
    pos = 0
    n = len(buf)
    while pos + 5 <= n:
        content_type = buf[pos]
        record_len = int.from_bytes(buf[pos + 3:pos + 5], "big")
        record_end = pos + 5 + record_len
        if record_end > n:
            break  # record not fully captured yet
        if content_type == HANDSHAKE_CONTENT_TYPE:
            hbody = buf[pos + 5:record_end]
            hpos = 0
            hn = len(hbody)
            while hpos + 4 <= hn:
                htype = hbody[hpos]
                hlen = int.from_bytes(hbody[hpos + 1:hpos + 4], "big")
                hend = hpos + 4 + hlen
                if hend > hn:
                    break
                if htype in (CLIENT_HELLO, SERVER_HELLO) and htype not in found:
                    found[htype] = hbody[hpos + 4:hend]
                hpos = hend
        pos = record_end
    return found


def _parse_extensions(body: bytes, pos: int) -> list:
    extensions = []
    if pos >= len(body):
        return extensions
    ext_total_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    end = pos + ext_total_len
    while pos + 4 <= end:
        etype = int.from_bytes(body[pos:pos + 2], "big")
        elen = int.from_bytes(body[pos + 2:pos + 4], "big")
        pos += 4
        edata = body[pos:pos + elen]
        pos += elen
        extensions.append(Extension(etype, edata))
    return extensions


def parse_client_hello(body: bytes) -> ClientHello:
    pos = 0
    version = int.from_bytes(body[0:2], "big")
    pos += 2 + 32  # version + random

    sid_len = body[pos]
    pos += 1 + sid_len

    cs_len = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    cipher_suites = [
        int.from_bytes(body[pos + i:pos + i + 2], "big") for i in range(0, cs_len, 2)
    ]
    pos += cs_len

    comp_len = body[pos]
    pos += 1 + comp_len

    extensions = _parse_extensions(body, pos)

    supported_groups, ec_point_formats = [], []
    sni, alpn, sig_algs, sup_versions = None, [], [], []

    for ext in extensions:
        data = ext.data
        if ext.type == EXT_SUPPORTED_GROUPS and len(data) >= 2:
            n = int.from_bytes(data[0:2], "big")
            supported_groups = [
                int.from_bytes(data[2 + i:4 + i], "big") for i in range(0, n, 2)
            ]
        elif ext.type == EXT_EC_POINT_FORMATS and len(data) >= 1:
            n = data[0]
            ec_point_formats = list(data[1:1 + n])
        elif ext.type == EXT_SERVER_NAME and len(data) >= 5:
            p = 2  # skip server_name_list length
            name_len = int.from_bytes(data[p + 1:p + 3], "big")
            sni = data[p + 3:p + 3 + name_len].decode("ascii", errors="replace")
        elif ext.type == EXT_ALPN and len(data) >= 2:
            p = 2
            protos = []
            list_end = 2 + int.from_bytes(data[0:2], "big")
            while p < list_end:
                plen = data[p]
                p += 1
                protos.append(data[p:p + plen].decode("ascii", errors="replace"))
                p += plen
            alpn = protos
        elif ext.type == EXT_SIGNATURE_ALGORITHMS and len(data) >= 2:
            n = int.from_bytes(data[0:2], "big")
            sig_algs = [
                int.from_bytes(data[2 + i:4 + i], "big") for i in range(0, n, 2)
            ]
        elif ext.type == EXT_SUPPORTED_VERSIONS and len(data) >= 1:
            n = data[0]
            sup_versions = [
                int.from_bytes(data[1 + i:3 + i], "big") for i in range(0, n, 2)
            ]

    return ClientHello(
        version=version,
        cipher_suites=cipher_suites,
        extensions=extensions,
        supported_groups=supported_groups,
        ec_point_formats=ec_point_formats,
        sni=sni,
        alpn=alpn,
        signature_algorithms=sig_algs,
        supported_versions=sup_versions,
    )


def parse_server_hello(body: bytes) -> ServerHello:
    pos = 0
    version = int.from_bytes(body[0:2], "big")
    pos += 2 + 32  # version + random

    sid_len = body[pos]
    pos += 1 + sid_len

    cipher_suite = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2

    pos += 1  # compression method

    extensions = _parse_extensions(body, pos)
    return ServerHello(version=version, cipher_suite=cipher_suite, extensions=extensions)
