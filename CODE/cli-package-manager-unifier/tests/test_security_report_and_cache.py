"""Tests for the security report writer and PackageCacheDB."""
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false
import json
import os

from src.utils.security_report import write_security_report, write_security_report_markdown
from src.utils.package_cache import PackageCacheDB


# ------------------------------------------------------------------
# write_security_report
# ------------------------------------------------------------------

class TestSecurityReport:
    def test_writes_json_file(self, tmp_path):
        scan = {"decision": "allow", "coverage": 3, "counts": {}, "findings": [], "providers": {}}
        path = write_security_report(
            action="install",
            package_name="requests",
            manager_name="pip3",
            scan_result=scan,
            operation_status="completed",
            operation_success=True,
            output_dir=str(tmp_path),
        )
        assert path is not None
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["action"] == "install"
        assert data["package"] == "requests"
        assert data["operation"]["success"] is True

    def test_filename_contains_action_and_package(self, tmp_path):
        path = write_security_report(
            action="upgrade",
            package_name="flask",
            manager_name="pip3",
            scan_result={"decision": "warn"},
            operation_status="completed",
            operation_success=True,
            output_dir=str(tmp_path),
        )
        assert path is not None
        assert "upgrade" in os.path.basename(path)
        assert "flask" in os.path.basename(path)

    def test_sanitises_special_chars_in_filename(self, tmp_path):
        path = write_security_report(
            action="install",
            package_name="@scope/pkg",
            manager_name="npm",
            scan_result={},
            operation_status="completed",
            operation_success=True,
            output_dir=str(tmp_path),
        )
        assert path is not None
        # Should not contain slashes in filename
        basename = os.path.basename(path)
        assert "/" not in basename and "\\" not in basename

    def test_writes_markdown_file(self, tmp_path):
        scan = {
            "decision": "warn",
            "reason": "Medium/high severity findings detected",
            "coverage": 2,
            "counts": {"critical": 0, "high": 1, "medium": 2, "low": 0},
            "findings": [
                {
                    "id": "GHSA-1234",
                    "severity": "high",
                    "summary": "Example high finding",
                    "source": "github_advisory",
                }
            ],
            "providers": {},
        }
        path = write_security_report_markdown(
            action="install",
            package_name="Werkzeug",
            manager_name="pip3",
            scan_result=scan,
            operation_status="pre-install",
            operation_success=False,
            output_dir=str(tmp_path),
        )
        assert path is not None
        assert path.endswith(".md")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert "# Security Report" in content
        assert "**High:** 1" in content
        assert "GHSA-1234" in content


# ------------------------------------------------------------------
# PackageCacheDB
# ------------------------------------------------------------------

class TestPackageCacheDB:
    def test_add_and_get(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        with PackageCacheDB(db_path=db_path) as db:
            db.add_package("requests", "2.31.0", "pip3")
            pkgs = db.get_packages()
        assert len(pkgs) == 1
        assert pkgs[0] == ("requests", "2.31.0", "pip3")

    def test_unique_constraint(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        with PackageCacheDB(db_path=db_path) as db:
            db.add_package("requests", "2.31.0", "pip3")
            db.add_package("requests", "2.31.0", "pip3")  # duplicate
            pkgs = db.get_packages()
        assert len(pkgs) == 1  # only one row

    def test_context_manager(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        with PackageCacheDB(db_path=db_path) as db:
            db.add_package("flask", "3.0.0", "pip3")
        # Verify file exists after context exit
        assert os.path.isfile(db_path)
