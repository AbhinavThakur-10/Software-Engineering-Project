import time

from src.utils.security_cache import SecurityScanCache


def test_security_cache_set_get(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache = SecurityScanCache(cache_file=str(cache_file), ttl_seconds=30)

    cache.set("key1", {"decision": "allow"})
    value = cache.get("key1")

    assert value is not None
    assert value["decision"] == "allow"


def test_security_cache_expires(tmp_path):
    cache_file = tmp_path / "cache.json"
    cache = SecurityScanCache(cache_file=str(cache_file), ttl_seconds=1)

    cache.set("key2", {"decision": "warn"}, ttl_seconds=1)
    time.sleep(1.1)

    assert cache.get("key2") is None
