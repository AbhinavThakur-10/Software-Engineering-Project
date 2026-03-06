from src.utils.security_aggregator import SecurityAggregator


def test_scoring_blocks_on_critical_findings():
    aggregator = SecurityAggregator(api_key="dummy")

    providers = {
        "osv": {"status": "ok", "findings": [{"id": "CVE-1", "severity": "critical", "summary": "critical issue"}]},
        "github_advisory": {"status": "ok", "findings": []},
        "oss_index": {"status": "ok", "findings": []},
        "virustotal": {"status": "unavailable", "findings": []},
    }

    scored = aggregator._score(providers)

    assert scored["decision"] == "block"


def test_scoring_warns_on_medium_or_high_findings():
    aggregator = SecurityAggregator(api_key="dummy")

    providers = {
        "osv": {"status": "ok", "findings": [{"id": "CVE-2", "severity": "medium", "summary": "medium issue"}]},
        "github_advisory": {"status": "ok", "findings": []},
        "oss_index": {"status": "error", "findings": []},
        "virustotal": {"status": "unavailable", "findings": []},
    }

    scored = aggregator._score(providers)

    assert scored["decision"] == "warn"


def test_scoring_allows_when_no_findings_and_sufficient_coverage():
    aggregator = SecurityAggregator(api_key="dummy")

    providers = {
        "osv": {"status": "ok", "findings": []},
        "github_advisory": {"status": "ok", "findings": []},
        "oss_index": {"status": "error", "findings": []},
        "virustotal": {"status": "unavailable", "findings": []},
    }

    scored = aggregator._score(providers)

    assert scored["decision"] == "allow"


def test_fallback_logic_warns_when_coverage_insufficient():
    aggregator = SecurityAggregator(api_key="dummy")

    providers = {
        "osv": {"status": "error", "findings": []},
        "github_advisory": {"status": "error", "findings": []},
        "oss_index": {"status": "ok", "findings": []},
        "virustotal": {"status": "unavailable", "findings": []},
    }

    scored = aggregator._score(providers)

    assert scored["decision"] == "warn"


def test_analyze_uses_provider_collection(monkeypatch):
    aggregator = SecurityAggregator(api_key="dummy")

    fake_providers = {
        "osv": {"status": "ok", "findings": []},
        "github_advisory": {"status": "ok", "findings": []},
        "oss_index": {"status": "ok", "findings": []},
        "virustotal": {"status": "unavailable", "findings": []},
    }

    monkeypatch.setattr(aggregator, "_collect_provider_results", lambda *args, **kwargs: fake_providers)

    result = aggregator.analyze("requests", "pip3")

    assert result["decision"] == "allow"
    assert result["providers"]["osv"]["status"] == "ok"
