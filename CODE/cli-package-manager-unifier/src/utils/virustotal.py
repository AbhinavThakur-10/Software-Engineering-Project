"""VirusTotal API helpers for hash scanning."""
import os
import hashlib
import tempfile
import subprocess
import shutil
import requests
from typing import Optional, Dict, Any, cast
from urllib.parse import quote

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/{}"
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/files"


def get_virustotal_api_key() -> str:
    """Return VirusTotal API key from environment variable VIRUSTOTAL_API_KEY."""
    raw = os.environ.get("VIRUSTOTAL_API_KEY", "") or ""
    return raw.strip()  # remove any accidental whitespace


def scan_file_hash_with_virustotal(file_hash: str, api_key: str) -> Dict[str, Any]:
    """Query VirusTotal for a file hash."""
    headers = {"x-apikey": api_key}
    url = VIRUSTOTAL_API_URL.format(file_hash)
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.json()
    else:
        return {"error": resp.status_code, "message": resp.text}


def upload_file_to_virustotal(file_path: str, api_key: str) -> Dict[str, Any]:
    """Upload a file to VirusTotal for scanning."""
    headers = {"x-apikey": api_key}
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        resp = requests.post(VIRUSTOTAL_SCAN_URL, headers=headers, files=files)
    if resp.status_code == 200:
        return resp.json()
    else:
        return {"error": resp.status_code, "message": resp.text}


def calculate_file_hash(file_path: str) -> str:
    """Return SHA-256 of a file."""
    sha256_hash = hashlib.sha256()
    # read in chunks to avoid memory issues with large files
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def _download_pip_artifact(package_name: str, tmpdir: str, version: Optional[str] = None) -> Optional[str]:
    """Download pip artifact (no deps) and return hash.

    When *version* is supplied the download is pinned to that exact version
    (``name==version``), eliminating the TOCTOU window between scan and install.
    """
    # Build the version-pinned specifier, e.g. "requests==2.31.0"
    if version:
        base = package_name.split("==")[0].split("@")[0].strip()
        specifier = f"{base}=={version}"
    else:
        specifier = package_name

    # try pip3 first, fall back to python -m pip
    cmd = ['pip3', 'download', '--no-deps', specifier, '-d', tmpdir]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        cmd2 = ['python', '-m', 'pip', 'download', '--no-deps', specifier, '-d', tmpdir]
        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        if result2.returncode != 0:
            return None
    # find the downloaded file and hash it
    for fname in os.listdir(tmpdir):
        fpath = os.path.join(tmpdir, fname)
        if os.path.isfile(fpath):
            return calculate_file_hash(fpath)
    return None


def _get_npm_registry() -> str:
    """Return npm registry URL (default https://registry.npmjs.org/)."""
    try:
        res = subprocess.run(['npm', 'config', 'get', 'registry'], capture_output=True, text=True)
        reg = res.stdout.strip()
        if reg and reg != 'undefined':
            return reg.rstrip('/') + '/'
    except Exception:
        pass
    # fallback to default npm registry
    return 'https://registry.npmjs.org/'


def _get_npm_metadata(package_name: str) -> Optional[Dict[str, Any]]:
    """Fetch npm metadata via `npm view --json`."""
    try:
        res = subprocess.run(['npm', 'view', package_name, '--json'], capture_output=True, text=True)
        if res.returncode != 0 or not res.stdout.strip():
            return None
        import json as _json
        return _json.loads(res.stdout)
    except Exception:
        return None

def _get_npm_latest_tarball_from_registry(package_name: str, registry: str) -> Optional[str]:
    """Return latest dist.tarball from registry (handles scopes)."""
    try:
        encoded = quote(package_name, safe='@/')
        url = f"{registry}{encoded}/latest"
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return None
        data = r.json()
        dist = data.get('dist')
        if isinstance(dist, dict):
            tar = dist.get('tarball')
            if isinstance(tar, str) and tar:
                return tar
        return None
    except Exception:
        return None


def _construct_npm_tarball_url(package_name: str, version: str, registry: str) -> str:
    """Construct tarball URL from name/version/registry (handles scopes)."""
    # scoped packages like @scope/name need special URL structure
    if package_name.startswith('@'):
        # @scope/name -> registry@scope/name/-/name-version.tgz
        scope, name = package_name.split('/', 1)
        scope = scope[1:]  # remove leading @
        return f"{registry}{scope}/{name}/-/" + f"{name}-{version}.tgz"
    else:
        return f"{registry}{package_name}/-/" + f"{package_name}-{version}.tgz"


def _download_npm_tarball(url: str, tmpdir: str, package_name: str) -> Optional[str]:
    """Download npm tarball and return hash."""
    try:
        tgz_path = os.path.join(tmpdir, f"{package_name}.tgz")
        # stream download to avoid loading entire file in memory
        with requests.get(url, stream=True, timeout=30) as r:
            if r.status_code != 200:
                return None
            with open(tgz_path, 'wb') as f:
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)
        return calculate_file_hash(tgz_path)
    except Exception:
        return None


def _npm_pack_fallback(package_name: str, tmpdir: str) -> Optional[str]:
    """Run `npm pack <name>` in CWD and hash result."""
    try:
        res = subprocess.run(['npm', 'pack', package_name], capture_output=True, text=True)
        if res.returncode != 0 or not res.stdout.strip():
            return None
        # npm pack outputs the filename on last line
        packed_name = res.stdout.strip().splitlines()[-1]
        src = os.path.join(os.getcwd(), packed_name)
        if not os.path.isfile(src):
            return None
        dst = os.path.join(tmpdir, packed_name)
        shutil.move(src, dst)
        return calculate_file_hash(dst)
    except Exception:
        return None


def download_package_and_get_hash(
    package_name: str,
    manager: str,
    version: Optional[str] = None,
) -> Optional[str]:
    """Download the **exact** package artifact and return its SHA-256 hash.

    TOCTOU fix: when *version* is provided we download that specific release
    rather than letting the registry resolve "latest" independently from what
    the package manager will ultimately install.

    Supported ecosystems: pip3, npm, yarn, pnpm.
    """
    tmpdir = tempfile.mkdtemp(prefix="pkgscan_")
    try:
        if manager == 'pip3':
            return _download_pip_artifact(package_name, tmpdir, version=version)
        if manager in {'npm', 'yarn', 'pnpm'}:
            registry = _get_npm_registry()
            tarball_url: Optional[str] = None

            # If we already know the exact version, build the URL directly
            # without an extra registry round-trip — this is the TOCTOU-safe path.
            if version:
                tarball_url = _construct_npm_tarball_url(package_name, version, registry)
            else:
                # Fall back to the original discovery flow (scan-only path, no version pinned)
                meta = _get_npm_metadata(package_name)
                if isinstance(meta, dict):
                    dist_obj = meta.get('dist')
                    if isinstance(dist_obj, dict):
                        dist_dict = cast(Dict[str, Any], dist_obj)
                        t = dist_dict.get('tarball')
                        if isinstance(t, str) and t:
                            tarball_url = t
                if not tarball_url:
                    tarball_url = _get_npm_latest_tarball_from_registry(package_name, registry)
                if not tarball_url and isinstance(meta, dict):
                    v = meta.get('version') if isinstance(meta.get('version'), str) else None
                    if v:
                        tarball_url = _construct_npm_tarball_url(package_name, v, registry)

            if isinstance(tarball_url, str) and tarball_url:
                hash_val = _download_npm_tarball(tarball_url, tmpdir, package_name)
                if hash_val:
                    return hash_val
            # Fallback to npm pack
            return _npm_pack_fallback(package_name, tmpdir)
        return None
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass
