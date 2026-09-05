import hashlib

from tls_fingerprint.tls_parser import ClientHello, Extension, ServerHello
from tls_fingerprint.ja3 import ja3, ja3s, GREASE_VALUES


def test_grease_values_match_rfc8701():
    expected = {int(f"{h}a{h}a", 16) for h in "0123456789abcdef"}
    assert GREASE_VALUES == expected
    assert len(GREASE_VALUES) == 16


def test_ja3_filters_grease_and_formats_fields():
    ch = ClientHello(
        version=771,
        cipher_suites=[0x0A0A, 4865, 4866],
        extensions=[Extension(0x1A1A, b""), Extension(0, b""), Extension(10, b"")],
        supported_groups=[0x2A2A, 29, 23],
        ec_point_formats=[0],
    )

    expected_string = "771,4865-4866,0-10,29-23,0"
    expected_hash = hashlib.md5(expected_string.encode()).hexdigest()

    ja3_string, ja3_hash = ja3(ch)
    assert ja3_string == expected_string
    assert ja3_hash == expected_hash


def test_ja3s_filters_grease_and_formats_fields():
    sh = ServerHello(
        version=771,
        cipher_suite=4865,
        extensions=[Extension(0x3A3A, b""), Extension(43, b"")],
    )

    expected_string = "771,4865,43"
    expected_hash = hashlib.md5(expected_string.encode()).hexdigest()

    s_string, s_hash = ja3s(sh)
    assert s_string == expected_string
    assert s_hash == expected_hash


def test_ja3_empty_lists_still_produce_valid_string():
    ch = ClientHello(version=769, cipher_suites=[], extensions=[])
    ja3_string, _ = ja3(ch)
    assert ja3_string == "769,,,,"
