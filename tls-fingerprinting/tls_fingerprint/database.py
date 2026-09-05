"""JSON-backed reference database of known fingerprints -> client labels.

Seeded empty by design: publicly "known" JA3 hashes drift as libraries update
their default cipher/extension lists, so the tool ships with a `--learn`
workflow (see cli.py) to build a *locally verified* reference set instead of
trusting stale hardcoded values.
"""
import json
import os

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "known_fingerprints.json")


class FingerprintDB:
    def __init__(self, path=None):
        self.path = os.path.abspath(path or DEFAULT_DB_PATH)
        self._data = {"ja3": {}, "ja3s": {}, "ja4": {}}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
            for kind in ("ja3", "ja3s", "ja4"):
                self._data[kind].update(on_disk.get(kind, {}))

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True)

    def add(self, kind: str, fp_hash: str, label: str):
        self._data.setdefault(kind, {})[fp_hash] = label
        self.save()

    def lookup(self, kind: str, fp_hash: str):
        return self._data.get(kind, {}).get(fp_hash)

    def list_all(self):
        return self._data
