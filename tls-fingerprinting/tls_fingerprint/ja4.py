"""JA4 client fingerprinting (FoxIO spec, TCP/TLS ClientHello variant only).

This is a best-effort, simplified reimplementation of the publicly documented
JA4 algorithm (https://github.com/FoxIO-LLC/ja4) covering the core
ClientHello case. It exists to demonstrate *why* JA4 is more resistant to
extension-order randomization than JA3 (it sorts ciphers/extensions before
hashing) -- for production-grade fingerprinting, use the official ja4 library.

Format: JA4_a_JA4_b_JA4_c
  JA4_a: protocol + tls_version + sni_flag + cipher_count(2) + ext_count(2) + alpn(2)
  JA4_b: truncated SHA256 of sorted, comma-joined cipher suites (hex)
  JA4_c: truncated SHA256 of sorted extensions (hex, excluding SNI/ALPN) + "_" +
         signature algorithms (hex, original order)
"""
import hashlib

from .tls_parser import ClientHello, EXT_SERVER_NAME, EXT_ALPN
from .ja3 import GREASE_VALUES

_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
}


def _version_code(ch: ClientHello) -> str:
    versions = ch.supported_versions if ch.supported_versions else [ch.version]
    return _VERSION_CODES.get(max(versions), "00")


def _alpn_code(ch: ClientHello) -> str:
    if not ch.alpn:
        return "00"
    val = ch.alpn[0]
    if len(val) >= 2:
        return val[0] + val[-1]
    if val:
        return val * 2
    return "00"


def ja4(ch: ClientHello, protocol: str = "t") -> tuple:
    """Returns (human_readable_breakdown, ja4_fingerprint)."""
    ciphers = [c for c in ch.cipher_suites if c not in GREASE_VALUES]
    ext_types = [e.type for e in ch.extensions if e.type not in GREASE_VALUES]

    ja4_a = "{proto}{ver}{sni}{nc:02d}{ne:02d}{alpn}".format(
        proto=protocol,
        ver=_version_code(ch),
        sni="d" if ch.sni else "i",
        nc=min(len(ciphers), 99),
        ne=min(len(ext_types), 99),
        alpn=_alpn_code(ch),
    )

    cipher_hex_sorted = sorted(f"{c:04x}" for c in ciphers)
    ja4_b = hashlib.sha256(",".join(cipher_hex_sorted).encode()).hexdigest()[:12]

    ext_hex_sorted = sorted(
        f"{t:04x}" for t in ext_types if t not in (EXT_SERVER_NAME, EXT_ALPN)
    )
    sig_algs_hex = [f"{s:04x}" for s in ch.signature_algorithms]
    ja4_c_input = ",".join(ext_hex_sorted) + "_" + ",".join(sig_algs_hex)
    ja4_c = hashlib.sha256(ja4_c_input.encode()).hexdigest()[:12]

    fingerprint = f"{ja4_a}_{ja4_b}_{ja4_c}"
    breakdown = (
        f"a={ja4_a} ciphers={cipher_hex_sorted} "
        f"extensions={ext_hex_sorted} sig_algs={sig_algs_hex}"
    )
    return breakdown, fingerprint
