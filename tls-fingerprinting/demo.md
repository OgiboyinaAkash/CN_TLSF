# Demo Script — Proving TLS Fingerprinting Works

Run in this order:

## 1. Prove the core algorithm is correct (30 sec, no admin, no network)

```powershell
cd tls-fingerprinting
pytest -v
```

All 9 should pass — this shows JA3/JA4 hashing logic itself is correct, independent of capture.

## 2. Prove live identification works (needs 2 terminals)

Terminal A — **run PowerShell as Administrator**:

```powershell
python main.py identify --live --duration 15 --learn curl
```

Terminal B (regular, run within those 15 seconds):

```powershell
curl.exe https://example.com
```

Terminal A will print something like:

```
[ClientHello] flow=... sni='example.com'
  JA3  <hash>  match=UNKNOWN
  JA4  <hash>  match=UNKNOWN
  -> learned as 'curl'
```

That "learned as 'curl'" line is proof the pipeline works end-to-end: capture → parse → hash → store.

## 3. Prove recognition (not just learning)

Repeat step 2 with a different client (e.g. open a browser to any https site) using `--learn firefox` or `--learn chrome`, then run **without** `--learn`:

```powershell
python main.py identify --live --duration 30
```

and trigger `curl.exe https://example.com` again — this time it should print `match=curl` instead of `UNKNOWN`. That's the actual "it works" moment for the demo.

## 4. Show the database

```powershell
python main.py db list
```

Shows the JSON of hash → label entries you've built up.

## 5. (Optional, the strongest single proof for evaluators) JA3-vs-JA4 stability

Do step 2/3 with Chrome twice, in two separate browser sessions, hitting the same site:

```powershell
python main.py identify --live --duration 15 --learn chrome-run1
python main.py identify --live --duration 15 --learn chrome-run2
```

Show the two outputs side by side: **JA3 hash differs**, **JA4 hash is the same**. That single comparison demonstrates the exact concept the project is about.

## Fallback: no admin/Npcap available at demo time

Capture once via Wireshark to a `.pcap`, then replay anytime with no elevated privileges:

```powershell
python main.py identify --pcap sample.pcap
```
