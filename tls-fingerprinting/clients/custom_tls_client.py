"""A hand-rolled TLS client with a deliberately non-default cipher suite list
and TLS 1.3 disabled, so it produces a JA3/JA4 fingerprint distinct from
browsers, curl, and python-requests -- standing in for the kind of minimal
TLS client bots/malware C2 frameworks often use.

Usage:
    python clients/custom_tls_client.py <host> [--port 443]
"""
import argparse
import socket
import ssl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers(
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384"
    )
    ctx.options |= ssl.OP_NO_TLSv1_3  # avoid GREASE/TLS1.3 extensions for a stable fingerprint

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=args.host) as tls_sock:
            print(f"Connected to {args.host}:{args.port} using {tls_sock.version()} / {tls_sock.cipher()}")


if __name__ == "__main__":
    main()
