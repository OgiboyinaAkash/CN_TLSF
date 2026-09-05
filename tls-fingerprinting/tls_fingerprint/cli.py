import argparse
import json
import sys

from .capture import live_capture, read_pcap
from .database import FingerprintDB
from .ja3 import ja3, ja3s
from .ja4 import ja4
from .tls_parser import parse_client_hello, parse_server_hello


def _make_callbacks(db: FingerprintDB, learn_label: str):
    def on_client_hello(raw: bytes, key):
        ch = parse_client_hello(raw)
        ja3_str, ja3_hash = ja3(ch)
        _, ja4_hash = ja4(ch)

        print(f"[ClientHello] flow={key} sni={ch.sni!r}")
        print(f"  JA3  {ja3_hash}  match={db.lookup('ja3', ja3_hash) or 'UNKNOWN'}")
        print(f"       ({ja3_str})")
        print(f"  JA4  {ja4_hash}  match={db.lookup('ja4', ja4_hash) or 'UNKNOWN'}")

        if learn_label:
            db.add("ja3", ja3_hash, learn_label)
            db.add("ja4", ja4_hash, learn_label)
            print(f"  -> learned as '{learn_label}'")
        print()

    def on_server_hello(raw: bytes, key):
        sh = parse_server_hello(raw)
        s_str, s_hash = ja3s(sh)
        print(f"[ServerHello] flow={key}")
        print(f"  JA3S {s_hash}  match={db.lookup('ja3s', s_hash) or 'UNKNOWN'}")
        print(f"       ({s_str})")
        if learn_label:
            db.add("ja3s", s_hash, f"{learn_label}-server")
        print()

    return on_client_hello, on_server_hello


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="tls-fingerprint",
        description="Passive TLS client fingerprinting tool (JA3 / JA3S / JA4).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ident = sub.add_parser("identify", help="Capture/read TLS handshakes and compute fingerprints")
    source = ident.add_mutually_exclusive_group(required=True)
    source.add_argument("--live", action="store_true", help="Sniff live traffic (needs admin + Npcap on Windows)")
    source.add_argument("--pcap", metavar="FILE", help="Read handshakes from a .pcap/.pcapng file")
    ident.add_argument("--iface", default=None, help="Interface name for --live (default: Scapy's default)")
    ident.add_argument("--filter", default="tcp", help="BPF filter for --live (default: 'tcp')")
    ident.add_argument("--duration", type=int, default=None, help="Seconds to capture for --live")
    ident.add_argument("--count", type=int, default=None, help="Packet count limit for --live")
    ident.add_argument("--learn", metavar="LABEL", default=None, help="Store the resulting fingerprint(s) under LABEL")
    ident.add_argument("--db", default=None, help="Path to the fingerprint database JSON")

    db_parser = sub.add_parser("db", help="Inspect the local fingerprint database")
    db_parser.add_argument("--db", default=None, help="Path to the fingerprint database JSON")
    db_sub = db_parser.add_subparsers(dest="db_command", required=True)
    db_sub.add_parser("list", help="List all known fingerprints")
    db_add = db_sub.add_parser("add", help="Manually register a fingerprint")
    db_add.add_argument("kind", choices=["ja3", "ja3s", "ja4"])
    db_add.add_argument("hash")
    db_add.add_argument("label")

    args = parser.parse_args(argv)

    if args.command == "identify":
        db = FingerprintDB(args.db)
        on_ch, on_sh = _make_callbacks(db, args.learn)
        if args.live:
            print("Starting live capture..." + (f" ({args.duration}s)" if args.duration else " (Ctrl+C to stop)"))
            try:
                live_capture(
                    iface=args.iface,
                    bpf_filter=args.filter,
                    duration=args.duration,
                    packet_count=args.count,
                    on_client_hello=on_ch,
                    on_server_hello=on_sh,
                )
            except PermissionError:
                print(
                    "Permission denied. On Windows, run this terminal as Administrator "
                    "(Npcap requires elevated privileges for live capture).",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            read_pcap(args.pcap, on_client_hello=on_ch, on_server_hello=on_sh)

    elif args.command == "db":
        db = FingerprintDB(args.db)
        if args.db_command == "list":
            print(json.dumps(db.list_all(), indent=2, sort_keys=True))
        elif args.db_command == "add":
            db.add(args.kind, args.hash, args.label)
            print(f"Added {args.kind}:{args.hash} -> {args.label}")


if __name__ == "__main__":
    main()
