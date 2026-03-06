import pytest

from src.utils.virustotal import download_package_and_get_hash


@pytest.mark.parametrize("manager", ["yarn", "pnpm"])
def test_download_hash_uses_npm_path_for_yarn_and_pnpm(monkeypatch, manager):
    monkeypatch.setattr("src.utils.virustotal._get_npm_registry", lambda: "https://registry.npmjs.org/")
    monkeypatch.setattr("src.utils.virustotal._get_npm_metadata", lambda package: {"dist": {"tarball": "https://example.com/pkg.tgz"}})
    monkeypatch.setattr("src.utils.virustotal._download_npm_tarball", lambda url, tmpdir, package: "hash123")

    result = download_package_and_get_hash("example-package", manager)

    assert result == "hash123"


def test_download_hash_uses_pip_path(monkeypatch):
    monkeypatch.setattr("src.utils.virustotal._download_pip_artifact", lambda package, tmpdir: "piphash")

    result = download_package_and_get_hash("requests", "pip3")

    assert result == "piphash"
