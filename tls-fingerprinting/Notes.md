# TLS Fingerprinting (Project 11) — Concepts, Implementation, and Demo Guide

## 1. What the project is actually asking for

Per `../CN_project.pdf` (Project ID 11) and `README.md`:

> Build a tool that **passively** captures TLS handshakes and computes JA3/JA4 fingerprints to identify **≥5 distinct clients** purely from their handshake — no decryption, no payload inspection — and demonstrate the JA3 weakness that JA4 was built to fix (Chrome's extension-order randomization).

"Passive" and "purely from the handshake" are the two constraints that shape every design decision in this codebase: you never touch encrypted application data, and you never rely on anything beyond the `ClientHello`/`ServerHello` bytes, which are sent in plaintext before encryption kicks in.

---

## 2. The TLS handshake fields you're actually reading

A TLS record on the wire looks like:

```
[1 byte content_type][2 bytes version][2 bytes length][payload...]
```

`content_type == 22` means "Handshake". Inside that payload sits a handshake message:

```
[1 byte handshake_type][3 bytes length][body...]
```

`handshake_type == 1` is `ClientHello`, `2` is `ServerHello`. This nesting (record layer wrapping handshake layer) is exactly what `tls_fingerprint/tls_parser.py:48-77` (`try_extract_handshakes`) walks — it scans concatenated record bytes, and for each complete record whose `content_type` is Handshake, it further scans the handshake sub-messages looking for type 1 or 2. This is the whole reason you didn't need `scapy`'s TLS layer or a real TLS stack: you only need to parse two fixed, unencrypted messages.

Inside a `ClientHello` body, the layout is (see `parse_client_hello`, `tls_fingerprint/tls_parser.py:97-165`):

```
version(2) | random(32) | session_id_len(1)+session_id | cipher_suites_len(2)+cipher_suites | compression_len(1)+compression | extensions_len(2)+extensions
```

Every field JA3/JA4 need — cipher suites, extension types, elliptic curves (`supported_groups`), point formats, SNI, ALPN, signature algorithms, supported TLS versions — lives in this one message. The parser walks the buffer byte-offset by byte-offset (`pos +=`), which is the standard way to decode TLV-ish binary protocols without a schema library.

**Extensions** are themselves a `[type(2)][len(2)][data]` list (`tls_fingerprint/tls_parser.py:80-94`), and `parse_client_hello` then re-interprets specific extension types (SNI=0x0000, supported_groups=0x000a, ec_point_formats=0x000b, sig_algs=0x000d, ALPN=0x0010, supported_versions=0x002b) to pull out their inner structure.

### GREASE — the one gotcha you must filter

RFC 8701: browsers (Chrome especially) insert fake cipher/extension/group values like `0x0A0A`, `0x1A1A`, `0x2A2A`, ... (16 values of the pattern `{h}A{h}A`) into every ClientHello. Their *purpose* is to break servers that hard-code an "allowed extensions" list (anti-ossification). If you hashed these in, **every single connection from the same browser would produce a different fingerprint**, defeating fingerprinting entirely. `tls_fingerprint/ja3.py:14-20` generates the 16 GREASE values programmatically and `_filter_grease` strips them from ciphers/extensions/groups before hashing — this is why `test_grease_values_match_rfc8701` and `test_ja3_filters_grease_and_formats_fields` exist in `tests/test_fingerprints.py`.

---

## 3. JA3 / JA3S

**Formula (Salesforce spec):**
```
JA3  = MD5( TLSVersion , Ciphers , Extensions , EllipticCurves , EllipticCurvePointFormats )
JA3S = MD5( TLSVersion , Cipher , Extensions )
```
fields joined by `,`, lists joined by `-`, **in the order they appeared on the wire**.

`tls_fingerprint/ja3.py:23-38` does exactly this: filter GREASE from ciphers/extensions/curves, leave point formats as-is (spec doesn't GREASE those), join with `-`, join the five fields with `,`, MD5 the string. JA3S (`tls_fingerprint/ja3.py:41-50`) is the same idea for the server's single chosen cipher.

Why order matters here: JA3 is **positional** — two ClientHellos with identical ciphers/extensions but listed in different order hash to *different* MD5s, because the comma/dash-joined string itself differs before hashing.

---

## 4. Why JA3 breaks — and why JA4 exists

Since ~2020, Chrome (and Chromium-based browsers) **randomizes the order of TLS extensions per connection** deliberately, as an anti-fingerprinting/anti-ossification measure. Since JA3 is order-sensitive, the *same* Chrome installation produces a *different* JA3 hash on every connection. This is the core "weakness to surface" the project asks for.

**JA4 (FoxIO spec)** fixes this by **sorting** before hashing, so wire order becomes irrelevant. `tls_fingerprint/ja4.py:45-74` builds three parts:

- **`JA4_a`** — a compact plaintext descriptor: protocol (`t`=TCP), TLS version code (`13`/`12`/...), `d`/`i` for SNI present/absent, 2-digit cipher count, 2-digit extension count, first+last ALPN chars. E.g. `t13d0303h2` from `test_ja4_format_structure`.
- **`JA4_b`** — SHA256 (truncated to 12 hex chars) of the cipher suites **sorted** as hex strings, comma-joined (`tls_fingerprint/ja4.py:59-60`).
- **`JA4_c`** — SHA256 (truncated) of **sorted** extension types (excluding SNI/ALPN, since those are already captured in `JA4_a`), concatenated with the signature-algorithm list (kept in original order, since sig-algs are a client preference-ranking, not something Chrome shuffles) (`tls_fingerprint/ja4.py:62-67`).

Because both `JA4_b` and `JA4_c` sort their inputs first, shuffling the *wire order* of ciphers or extensions produces **byte-identical** sorted lists → identical hash. That's the entire mechanism by which JA4 survives Chrome's randomization while JA3 doesn't — same input set, different join order for JA3 (order preserved) vs. same output for JA4 (order discarded).

---

## 5. Capture pipeline — passive, protocol-agnostic sniffing + reassembly

`tls_fingerprint/capture.py` is the "passive" half of the tool:

- `live_capture` wraps `scapy.sniff` with a BPF filter (default `"tcp"`) and a callback per packet — this is pure passive observation, no socket of your own, no interaction with the connection.
- `read_pcap` replays a `.pcap` through the same callback machinery, so the exact same fingerprint logic works offline on a captured file with no admin rights needed (this is your no-admin demo path).
- **TCP reassembly problem**: a ClientHello can be split across multiple TCP segments (common when SNI + a long extension list exceeds one MTU). `HandshakeCollector` (`tls_fingerprint/capture.py:32-61`) keys a `FlowBuffer` per `(src_ip, sport, dst_ip, dport)` 4-tuple, and every arriving payload is appended (`tls_fingerprint/capture.py:19-29`) until `try_extract_handshakes` finds a *complete* handshake message in the accumulated bytes. This is why the module docstring calls out the simplifying assumption: it assumes in-order delivery (true for essentially all localhost/LAN captures), rather than implementing full TCP sequence-number-based reassembly — a reasonable, explicitly-documented scope cut for a fingerprinting demo tool rather than a production stack.
- A `max_bytes` cap (64KB) on `FlowBuffer` guards against a flow that never yields a parseable handshake (e.g., non-TLS traffic slipping past the BPF filter) from buffering forever.

---

## 6. Local reference database — why it's seeded empty

`tls_fingerprint/database.py` is a flat JSON store: `{ja3: {hash: label}, ja3s: {...}, ja4: {...}}`. It deliberately ships **empty** rather than pre-populated with "known" public JA3 hashes for curl/Chrome/etc. — the docstring explains why: public hash lists rot as libraries update their default cipher/extension sets, so a hardcoded table silently goes stale. Instead, `tls_fingerprint/cli.py` provides a `--learn LABEL` flag (`tls_fingerprint/cli.py:23-26,35-36`) that, while capturing, writes whatever fingerprint it just computed into the DB under that label — you're building a **locally verified ground truth**, not trusting someone else's table. This directly maps to the expected outcome: "a curated database against 5 distinct clients."

---

## 7. The 5th client — hand-rolled TLS socket

`clients/custom_tls_client.py` uses Python's `ssl` module directly with `set_ciphers(...)` pinned to a non-default list and `OP_NO_TLSv1_3` forced off (`clients/custom_tls_client.py:20-29`) — TLS 1.3 is disabled specifically to avoid GREASE injection and keep the fingerprint deterministic. This produces a cipher/version signature no mainstream browser or HTTP library would ever emit, standing in for what the project brief calls "malware/C2's role in security monitoring": off-the-shelf C2 frameworks and bots tend to use minimal, hand-rolled TLS stacks with static, unusual JA3s that visibly stick out from a baseline of curl/requests/Firefox/Chrome — the exact anomaly-detection use case JA3 was originally built for (Suricata/Zeek/Cisco IDS rules), as explained in the README's "Why JA3 *and* JA4?" section.

---

## 8. Running the demo to hit every expected outcome

The brief's expected outcomes, mapped to concrete commands:

**(a) Identify ≥5 distinct clients purely by fingerprint.**
Build the DB (from `README.md:65-81`), one elevated PowerShell per client, learning label captured *while* the client's own request fires in another terminal:

```powershell
# admin PowerShell, one per client — trigger the client's HTTPS request in a second terminal while this runs
python main.py identify --live --duration 15 --learn curl
python main.py identify --live --duration 15 --learn python-requests
python main.py identify --live --duration 15 --learn firefox
python main.py identify --live --duration 15 --learn chrome
python main.py identify --live --duration 15 --learn custom-client   # trigger: python clients/custom_tls_client.py example.com
```

Then verify recognition with **no `--learn`**:

```powershell
python main.py identify --live --duration 60
python main.py db list
```

Show the printed `match=<label>` (not `UNKNOWN`) for each, and `db list` showing 5 distinct JA3/JA4 hashes → labels.

**(b) Demonstrate JA3 instability vs. JA4 stability under Chrome's extension randomization** — this is the centerpiece finding the project wants surfaced:

```powershell
python main.py identify --live --duration 15 --learn chrome-run1
# close Chrome, reopen it fresh, hit a different/same HTTPS site
python main.py identify --live --duration 15 --learn chrome-run2
```

Compare the two console outputs side by side: the `JA3` hash differs between runs (or even between the two connections your `--filter` catches within one Chrome session — Chrome shuffles per-connection, not just per-launch), while the `JA4` hash stays the same. That side-by-side diff *is* the deliverable — screenshot or paste both `identify` outputs.

**(c) No-admin fallback / reproducibility** — capture once to a `.pcap` in Wireshark, then re-run offline:
```powershell
python main.py identify --pcap sample.pcap
```
Useful if live admin capture isn't available at demo time — same fingerprint logic, no privilege needed, and it's deterministic/replayable in front of evaluators.

**(d) Correctness baseline without any network dependency** — the test suite proves the parsing/hashing logic against hand-built synthetic ClientHello bytes (`tests/builders.py`), so you can open with this before the live demo to establish the math is right independent of network conditions:
```powershell
pytest -v
```
Point specifically at `test_ja3_filters_grease_and_formats_fields` (proves GREASE stripping + exact JA3 string format against a hand-computed MD5) and `test_ja4_format_structure` (proves the `t13d0303h2_<hash>_<hash>` structure) as your "the algorithm is provably correct" evidence, separate from "it works on real traffic."

**(e) Limitations to state explicitly** (the brief wants this framed, not hidden): JA3/JA4 are a *weak signal*. CDNs/TLS-terminating proxies multiplex many distinct backend clients behind one visible fingerprint, and unrelated software built on the same TLS library (e.g., two different tools both using OpenSSL defaults) can collide on identical hashes. That's why real detection pipelines pair fingerprints with destination reputation, timing, and volume — worth one slide/sentence so the demo doesn't overclaim JA3/JA4 as ground truth identification.
