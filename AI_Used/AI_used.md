# AI Usage Documentation — TLS Fingerprinting (Project ID 11)

## Tools

- **Claude Haiku 4.5**.

---

## Prompts

`tls_fingerprint/tls_parser.py` and `tls_fingerprint/ja3.py` were **not** built from AI prompts — they were manually adapted from a public reference repo (details in "Originality Check" below). Every other module was built with AI, from prompts describing the required behavior:

| Module | Prompt |
|---|---|
| `tls_fingerprint/ja4.py` | "we have ja3 working but chrome randomizes extension order so it keeps changing, can you add ja4 too since that one sorts stuff before hashing so it should stay stable" |
| `tls_fingerprint/capture.py` | "need a way to actually sniff live traffic with scapy and also read from a pcap file, and handle the case where the clienthello is split across a couple tcp packets" |
| `tls_fingerprint/database.py` | "how do we store the fingerprints we find so we can match them later, just something simple like a json file mapping hash to a label, and let us add new ones while capturing" |
| `tls_fingerprint/cli.py` | "can you wire everything into a cli, like `identify --live` or `--pcap`, a `--learn` flag to label whatever it captures, and a db command to list/add fingerprints manually" |
| `clients/custom_tls_client.py` | "we need a 5th client for the demo, something that doesn't look like curl/requests/browser, maybe a python script using ssl with a weird cipher list so its fingerprint is unique" |
| `tests/` (`builders.py` + `test_*.py`) | "we don't have a pcap to test with, can you write some tests that just build a fake clienthello in bytes and check the parser/fingerprints work on it" |

---

## Thought Process

The core fingerprinting logic (`tls_parser.py`, `ja3.py`) was kept manual rather than AI-generated, since that's the part the team wanted to fully understand and control byte-for-byte; AI was used for the surrounding infrastructure (capture, storage, CLI, custom client, tests) where a natural-language description of the required behavior was enough to get a correct first pass.

Each AI-built module was reviewed and tested on its own before moving to the next, rather than generating everything at once and debugging it as a whole — e.g. the JA3 GREASE-filtering behavior was checked against a specific test (`test_ja3_filters_grease_and_formats_fields`) rather than assumed correct because the code looked right.

---

## Step-by-Step Details

1. Gave the AI the project brief (Project ID 11 — TLS Fingerprinting) and asked it to propose a project structure/module layout for it.
2. Selected a public JA3 reference implementation and manually adapted it into `tls_parser.py` + `ja3.py`.
3. Used AI to build the remaining modules (`ja4.py`, `capture.py`, `database.py`, `cli.py`, `custom_tls_client.py`, `tests/`) from the prompts above.
4. Ran the full test suite (`pytest -v`, 9 tests, all passing) to validate the AI-built modules before accepting them.

---

## Originality Check

| This project's file | Reference repo | What matches |
|---|---|---|
| `tls_fingerprint/ja3.py` | [salesforce/ja3](https://github.com/salesforce/ja3) | Same list of GREASE values, same JA3 formula and field order, same extension codes used for curves/point-formats. Manually adapted, not written independently. |
| `tls_fingerprint/tls_parser.py` | [salesforce/ja3](https://github.com/salesforce/ja3) | Parses the ClientHello in the same order (version, session id, ciphers, compression, extensions). Rewritten by hand to drop the `dpkt` dependency the reference uses. |
