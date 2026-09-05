from tls_fingerprint.tls_parser import ClientHello, Extension
from tls_fingerprint.ja4 import ja4


def test_ja4_format_structure():
    ch = ClientHello(
        version=0x0303,
        cipher_suites=[0x0A0A, 0x1301, 0x1302, 0x1303],
        extensions=[
            Extension(0x1A1A, b""),
            Extension(0, b""),  # SNI
            Extension(0x0010, b""),  # ALPN
            Extension(43, b"\x02\x03\x04"),  # supported_versions -> TLS1.3
        ],
        sni="example.com",
        alpn=["h2"],
        signature_algorithms=[0x0403, 0x0804],
        supported_versions=[0x0304],
    )

    breakdown, fingerprint = ja4(ch)
    parts = fingerprint.split("_")

    assert len(parts) == 3
    a, b, c = parts
    assert a == "t13d0303h2"  # tcp, TLS1.3, sni present, 3 ciphers, 3 exts, alpn "h2"
    assert len(b) == 12
    assert len(c) == 12


def test_ja4_no_sni_no_alpn():
    ch = ClientHello(version=0x0303, cipher_suites=[0x1301], extensions=[])
    _, fingerprint = ja4(ch)
    a = fingerprint.split("_")[0]
    assert a.startswith("t")
    assert "i" in a  # no SNI -> "i" flag
    assert a.endswith("00")  # no ALPN
