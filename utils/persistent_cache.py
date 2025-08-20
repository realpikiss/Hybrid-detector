#!/usr/bin/env python3
"""
Simple JSON-backed persistent dictionary with best-effort atomic writes.
Usage:
    from utils.persistent_cache import PersistentDict
    cache = PersistentDict(Path('data/semantic_cache.json'))
    key = '123'
    if key in cache: val = cache[key]
    cache[key] = ('purpose', 'behavior')
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, MutableMapping
import tempfile

class PersistentDict(MutableMapping[str, Any]):
    def __init__(self, path: Path):
        self.path = Path(path)
        self._data = {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with self.path.open('r', encoding='utf-8') as f:
                    self._data = json.load(f)
            except Exception:
                # Corrupt or empty; start fresh
                self._data = {}
        else:
            self._data = {}

    def _flush(self):
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=self.path.name, dir=str(self.path.parent))
        try:
            with open(tmp_fd, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False)
            Path(tmp_path).replace(self.path)
        except Exception:
            # Best effort: ignore flush errors to avoid crashing detection
            pass

    # MutableMapping interface
    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._flush()

    def __delitem__(self, key: str) -> None:
        if key in self._data:
            del self._data[key]
            self._flush()

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get_tuple(self, key: str):
        v = self._data.get(key)
        if isinstance(v, list):
            return tuple(v)
        return v
