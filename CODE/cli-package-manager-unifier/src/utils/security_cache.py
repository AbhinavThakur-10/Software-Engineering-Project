"""Small JSON TTL cache for security scan results."""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional


class SecurityScanCache:
    """JSON-backed TTL cache for package scan results."""

    def __init__(self, cache_file: Optional[str] = None, ttl_seconds: int = 600) -> None:
        self.cache_file = cache_file or os.path.join(os.getcwd(), ".security_scan_cache.json")
        self.ttl_seconds = ttl_seconds

    def _load(self) -> Dict[str, Any]:
        if not os.path.isfile(self.cache_file):
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as file:
                data = json.load(file)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self, payload: Dict[str, Any]) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as file:
                json.dump(payload, file)
        except Exception:
            pass

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        data = self._load()
        item = data.get(key)
        if not isinstance(item, dict):
            return None

        expires_at = item.get("expires_at", 0)
        if not isinstance(expires_at, (int, float)) or time.time() > expires_at:
            data.pop(key, None)
            self._save(data)
            return None

        value = item.get("value")
        return value if isinstance(value, dict) else None

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        data = self._load()
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        data[key] = {
            "expires_at": time.time() + max(1, int(ttl)),
            "value": value,
        }
        self._save(data)
