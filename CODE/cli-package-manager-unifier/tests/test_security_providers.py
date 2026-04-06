from src.utils.security_providers import manager_to_github_ecosystem, scan_with_oss_index


def test_manager_to_github_ecosystem_maps_python_to_pip():
    assert manager_to_github_ecosystem("pip3") == "pip"
    assert manager_to_github_ecosystem("poetry") == "pip"


def test_oss_index_without_auth_maps_401_to_unavailable(monkeypatch):
    monkeypatch.delenv("OSSINDEX_USERNAME", raising=False)
    monkeypatch.delenv("OSSINDEX_TOKEN", raising=False)

    monkeypatch.setattr(
        "src.utils.security_providers._request_with_retries",
        lambda *args, **kwargs: {"ok": False, "status": "error", "error": '{"code":401,"message":"Authentication required"}'},
    )

    result = scan_with_oss_index("requests", "pip3", "2.32.5")

    assert result["status"] == "unavailable"
    assert "authentication required" in result["error"].lower()
