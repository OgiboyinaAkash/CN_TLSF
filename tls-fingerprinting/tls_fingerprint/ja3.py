"""JA3 / JA3S fingerprinting (Salesforce spec).

JA3  = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
JA3S = MD5(SSLVersion,Cipher,Extensions)

GREASE values (RFC 8701) are filler values TLS clients insert to prevent
protocol ossification; they must be excluded or every connection would hash
differently.
"""
import hashlib

from .tls_parser import ClientHello, ServerHello

GREASE_VALUES = frozenset(
    int(f"{h}a{h}a", 16) for h in "0123456789abcdef"
)


def _filter_grease(values):
    return [v for v in values if v not in GREASE_VALUES]


def ja3(ch: ClientHello) -> tuple:
    """Returns (ja3_string, ja3_md5_hash)."""
    ciphers = _filter_grease(ch.cipher_suites)
    ext_types = _filter_grease([e.type for e in ch.extensions])
    curves = _filter_grease(ch.supported_groups)
    points = ch.ec_point_formats

    ja3_string = "{},{},{},{},{}".format(
        ch.version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in ext_types),
        "-".join(str(c) for c in curves),
        "-".join(str(p) for p in points),
    )
    digest = hashlib.md5(ja3_string.encode()).hexdigest()
    return ja3_string, digest


def ja3s(sh: ServerHello) -> tuple:
    """Returns (ja3s_string, ja3s_md5_hash)."""
    ext_types = _filter_grease([e.type for e in sh.extensions])
    ja3s_string = "{},{},{}".format(
        sh.version,
        sh.cipher_suite,
        "-".join(str(e) for e in ext_types),
    )
    digest = hashlib.md5(ja3s_string.encode()).hexdigest()
    return ja3s_string, digest
