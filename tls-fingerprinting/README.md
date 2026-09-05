# TLS Fingerprinting

A tool that passively captures TLS `ClientHello`/`ServerHello` handshakes
(live or from a `.pcap`), computes **JA3 / JA3S / JA4** fingerprints, and
matches them against a locally curated reference database to identify the
client application -- purely from its handshake, with no decryption involved.

## Project structure

```
tls-fingerprinting/
  tls_fingerprint/
    tls_parser.py   # raw TLS record/handshake parsing (no external deps)
    ja3.py           # JA3 / JA3S (MD5, Salesforce spec)
    ja4.py           # JA4 client fingerprint (simplified FoxIO spec)
    capture.py       # live sniff + pcap replay, with TCP reassembly
    database.py      # JSON-backed fingerprint -> label store
    cli.py           # command-line entry point
  clients/
    custom_tls_client.py  # hand-rolled TLS client for a 5th, distinct fingerprint
  data/known_fingerprints.json  # your local reference database (starts empty)
  tests/             # unit tests (synthetic ClientHello builders, no network needed)
  main.py
```

## Setup

```powershell
cd tls-fingerprinting
pip install -r requirements-dev.txt
```

Npcap (bundled with Wireshark) is required for **live** capture on Windows.
You already have it installed. Live capture also requires the terminal to
be running **as Administrator**.

## Usage

Identify traffic from a pcap file (no admin needed):

```powershell
python main.py identify --pcap sample.pcap
```

Capture live traffic for 20 seconds and label the resulting fingerprint
(run this *while* the target client makes an HTTPS request):

```powershell
# in an elevated (Administrator) PowerShell
python main.py identify --live --duration 20 --learn curl
```

Inspect what's been learned so far:

```powershell
python main.py db list
```

Manually register a fingerprint you already know:

```powershell
python main.py db add ja3 <hash> "some-client"
```

## Building a 5-client reference database

The expected outcome is identifying **at least 5 distinct clients** purely
from their handshake. A practical way to do this on one machine:

1. `python main.py identify --live --duration 15 --learn curl` then run
   `curl.exe https://example.com` in another terminal.
2. Same again with `--learn python-requests`, triggering `pip install requests`
   + `python -c "import requests; requests.get('https://example.com')"`.
3. Same again with `--learn firefox`, opening any HTTPS site in Firefox.
4. Same again with `--learn chrome`, opening any HTTPS site in Chrome/Edge.
5. Same again with `--learn custom-client`, running:
   `python clients/custom_tls_client.py example.com`.

Then re-run `python main.py identify --live ...` without `--learn` at any
point afterwards and confirm each client is correctly matched by JA3/JA4
against the database you built.

## Why JA3 *and* JA4?

JA3 hashes the ClientHello's cipher list, extension list (in the order they
appear), curves, and point formats. It's simple and was long used in
IDS/EDR products (Suricata, Zeek, Cisco) to flag malware C2 traffic --
hand-rolled TLS clients (e.g. bots, off-the-shelf C2 frameworks) tend to
produce unusual, static JA3 hashes that stand out from mainstream browser
traffic.

**Limitation this project is meant to surface:** since ~2020, Chrome (and
Chromium-based browsers) intentionally *randomizes the order* of TLS
extensions per connection (a deliberate anti-ossification/anti-fingerprinting
measure). Because JA3 is order-sensitive, the *same* installation of Chrome
produces a *different* JA3 hash on every connection -- breaking naive
single-hash matching. JA4 was designed specifically to address this: it
sorts cipher suites and extensions before hashing, so it stays stable across
Chrome's extension-order permutation. You should be able to demonstrate this
directly: capture the same browser twice and show JA3 changing while JA4
(mostly) doesn't.

This also means JA3/JA4 alone are a *weak signal*, not proof -- CDNs/proxies
terminating TLS on behalf of many different clients, and legitimate software
built on the same TLS library as malware, can produce false positives or
collide. Real detection pipelines combine fingerprints with other signals
(destination reputation, timing, volume).

## Notes on the JA4 implementation

`ja4.py` implements the ClientHello (`t`/`q` + version + sni + counts + alpn,
followed by sorted-cipher and sorted-extension/sig-algs hashes) case of the
publicly documented [JA4 spec](https://github.com/FoxIO-LLC/ja4). It is a
simplified reference implementation for learning purposes, not a byte-exact
port of the official library -- for production use, use FoxIO's own tooling.

## Running tests

```powershell
pytest
```

Tests build synthetic ClientHello/ServerHello byte buffers by hand (see
`tests/builders.py`) so parsing and hashing logic can be verified without a
live capture or a checked-in pcap file.
