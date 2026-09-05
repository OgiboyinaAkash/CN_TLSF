from tls_fingerprint.tls_parser import try_extract_handshakes, parse_client_hello, CLIENT_HELLO

from .builders import build_client_hello_record


def test_extract_and_parse_complete_client_hello():
    record = build_client_hello_record(sni="example.com")
    found = try_extract_handshakes(record)

    assert CLIENT_HELLO in found
    ch = parse_client_hello(found[CLIENT_HELLO])

    assert ch.version == 0x0303
    assert ch.cipher_suites == [0x1301, 0x1302, 0x0A0A]
    assert ch.supported_groups == [0x001D, 0x0017, 0x0A0A]
    assert ch.ec_point_formats == [0]
    assert ch.sni == "example.com"


def test_incomplete_record_yields_nothing():
    record = build_client_hello_record()
    truncated = record[:-5]  # cut off the tail of the extensions
    assert try_extract_handshakes(truncated) == {}


def test_reassembly_across_two_feeds():
    from tls_fingerprint.capture import FlowBuffer

    record = build_client_hello_record()
    split = len(record) // 2

    buf = FlowBuffer()
    assert buf.feed(record[:split]) is None  # first half: not enough yet
    found = buf.feed(record[split:])  # second half completes the record
    assert CLIENT_HELLO in found
