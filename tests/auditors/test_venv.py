"""Tests for pentester.auditors.venv.VenvAuditor."""

from __future__ import annotations

import pickle
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from pentester.auditors.venv import VenvAuditor
from pentester.enums.auditor_key import AuditorKey


def _make_auditor(**kwargs) -> VenvAuditor:
    defaults = dict(
        auditor_class="pentester.auditors.garak.GarakAuditor",
        auditor_key=AuditorKey.GARAK,
        venv_path="/tmp/test_venv",
    )
    defaults.update(kwargs)
    return VenvAuditor(**defaults)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestInit:
    def test_auditor_key_property_returns_injected_key(self) -> None:
        auditor = _make_auditor(auditor_key=AuditorKey.GARAK)
        assert auditor.auditor_key == AuditorKey.GARAK

    def test_packages_combined_from_list_and_file(self, tmp_path: Path) -> None:
        req_file = tmp_path / "reqs.txt"
        req_file.write_text("garak==0.14.0\n# comment\n\nfpdf2>=2.7\n")
        auditor = _make_auditor(packages=["Mako>=1.3"], requirements_file=str(req_file))
        assert auditor._packages == ["Mako>=1.3", "garak==0.14.0", "fpdf2>=2.7"]

    def test_packages_from_list_only(self) -> None:
        auditor = _make_auditor(packages=["garak==0.14.0"])
        assert auditor._packages == ["garak==0.14.0"]

    def test_packages_from_file_only(self, tmp_path: Path) -> None:
        req_file = tmp_path / "reqs.txt"
        req_file.write_text("garak==0.14.0\n")
        auditor = _make_auditor(requirements_file=str(req_file))
        assert auditor._packages == ["garak==0.14.0"]

    def test_empty_packages_by_default(self) -> None:
        auditor = _make_auditor()
        assert auditor._packages == []

    def test_auditor_kwargs_stored(self) -> None:
        auditor = _make_auditor(scanner=None, settings=None)
        assert "scanner" in auditor._auditor_kwargs


# ---------------------------------------------------------------------------
# _read_requirements
# ---------------------------------------------------------------------------


class TestReadRequirements:
    def test_skips_comments(self, tmp_path: Path) -> None:
        req = tmp_path / "r.txt"
        req.write_text("# comment\ngarak==0.14.0\n")
        assert _make_auditor()._read_requirements(req) == ["garak==0.14.0"]

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        req = tmp_path / "r.txt"
        req.write_text("\n\ngarak==0.14.0\n\n")
        assert _make_auditor()._read_requirements(req) == ["garak==0.14.0"]

    def test_returns_all_valid_lines(self, tmp_path: Path) -> None:
        req = tmp_path / "r.txt"
        req.write_text("garak==0.14.0\nfpdf2>=2.7\nMako>=1.3\n")
        assert _make_auditor()._read_requirements(req) == [
            "garak==0.14.0",
            "fpdf2>=2.7",
            "Mako>=1.3",
        ]

    def test_strips_whitespace(self, tmp_path: Path) -> None:
        req = tmp_path / "r.txt"
        req.write_text("  garak==0.14.0  \n")
        assert _make_auditor()._read_requirements(req) == ["garak==0.14.0"]


# ---------------------------------------------------------------------------
# _setup_venv
# ---------------------------------------------------------------------------


class TestSetupVenv:
    def test_creates_venv_when_path_does_not_exist(self, tmp_path: Path) -> None:
        venv_path = str(tmp_path / "new_venv")
        auditor = _make_auditor(venv_path=venv_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            auditor._setup_venv()
        assert (
            call(["python", "-m", "venv", venv_path], check=True)
            in mock_run.call_args_list
        )

    def test_does_not_create_venv_when_path_exists(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            auditor._setup_venv()
        venv_create_call = call(["python", "-m", "venv", str(tmp_path)], check=True)
        assert venv_create_call not in mock_run.call_args_list

    def test_installs_packages_when_hash_differs(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path), packages=["garak==0.14.0"])
        (tmp_path / ".packages_hash").write_text("old_hash")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            auditor._setup_venv()
        assert (
            call([f"{tmp_path}/bin/pip", "install", "garak==0.14.0"], check=True)
            in mock_run.call_args_list
        )

    def test_skips_install_when_hash_matches(self, tmp_path: Path) -> None:
        import hashlib

        auditor = _make_auditor(venv_path=str(tmp_path), packages=["garak==0.14.0"])
        current_hash = hashlib.md5("garak==0.14.0".encode()).hexdigest()
        (tmp_path / ".packages_hash").write_text(current_hash)
        with patch("subprocess.run") as mock_run:
            auditor._setup_venv()
        mock_run.assert_not_called()

    def test_writes_hash_file_after_install(self, tmp_path: Path) -> None:
        import hashlib

        auditor = _make_auditor(venv_path=str(tmp_path), packages=["garak==0.14.0"])
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            auditor._setup_venv()
        expected_hash = hashlib.md5("garak==0.14.0".encode()).hexdigest()
        assert (tmp_path / ".packages_hash").read_text() == expected_hash

    def test_raises_on_venv_creation_failure(self, tmp_path: Path) -> None:
        venv_path = str(tmp_path / "new_venv")
        auditor = _make_auditor(venv_path=venv_path)
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, "venv")
        ):
            with pytest.raises(subprocess.CalledProcessError):
                auditor._setup_venv()

    def test_raises_on_pip_install_failure(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path), packages=["bad-package"])
        with patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, "pip")
        ):
            with pytest.raises(subprocess.CalledProcessError):
                auditor._setup_venv()


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAudit:
    def _make_probe_results(self) -> list:
        from pentester.auditors.models.probe_result import ProbeResult

        return [
            ProbeResult(
                auditor="garak",
                attack_category="dan",
                attack_type="Dan1",
                prompt="p",
                response="r",
                bypassed=False,
                score=0.0,
                metadata={},
            )
        ]

    def test_audit_calls_setup_venv(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        results = self._make_probe_results()
        with (
            patch.object(auditor, "_setup_venv") as mock_setup,
            patch("subprocess.run"),
            patch("tempfile.NamedTemporaryFile"),
            patch("builtins.open", mock_open(read_data=pickle.dumps(results))),
            patch("pathlib.Path.exists", return_value=True),
            patch("os.unlink"),
        ):
            auditor.audit()
        mock_setup.assert_called_once()

    def test_audit_raises_when_output_file_missing(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        with (
            patch.object(auditor, "_setup_venv"),
            patch("subprocess.run"),
            patch("tempfile.NamedTemporaryFile") as mock_tmp,
            patch("pathlib.Path.exists", return_value=False),
            patch("os.unlink"),
        ):
            mock_tmp.return_value.__enter__.return_value.name = "/tmp/missing.pkl"
            with pytest.raises(RuntimeError, match="without writing results"):
                auditor.audit()

    def test_audit_returns_deserialized_results(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        results = self._make_probe_results()
        output_file = tmp_path / "output.pkl"
        output_file.write_bytes(pickle.dumps(results))

        mock_tmp = MagicMock()
        mock_tmp.__enter__ = MagicMock(return_value=MagicMock(name=str(output_file)))
        mock_tmp.__exit__ = MagicMock(return_value=False)

        with (
            patch.object(auditor, "_setup_venv"),
            patch("subprocess.run"),
            patch("tempfile.NamedTemporaryFile", return_value=mock_tmp),
            patch("pathlib.Path.exists", return_value=True),
            patch("os.unlink"),
            patch("builtins.open", mock_open(read_data=pickle.dumps(results))),
        ):
            returned, _ = auditor.audit()
        assert len(returned) == 1

    def test_audit_deletes_output_file_on_success(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        results = self._make_probe_results()
        with (
            patch.object(auditor, "_setup_venv"),
            patch("subprocess.run"),
            patch("tempfile.NamedTemporaryFile") as mock_tmp,
            patch("pathlib.Path.exists", return_value=True),
            patch("os.unlink") as mock_unlink,
            patch("builtins.open", mock_open(read_data=pickle.dumps(results))),
        ):
            mock_tmp.return_value.__enter__.return_value.name = "/tmp/out.pkl"
            auditor.audit()
        mock_unlink.assert_called_once()

    def test_audit_deletes_output_file_on_failure(self, tmp_path: Path) -> None:
        auditor = _make_auditor(venv_path=str(tmp_path))
        with (
            patch.object(auditor, "_setup_venv"),
            patch(
                "subprocess.run", side_effect=subprocess.CalledProcessError(1, "python")
            ),
            patch("tempfile.NamedTemporaryFile") as mock_tmp,
            patch("pathlib.Path.exists", return_value=True),
            patch("os.unlink") as mock_unlink,
        ):
            mock_tmp.return_value.__enter__.return_value.name = "/tmp/out.pkl"
            with pytest.raises(subprocess.CalledProcessError):
                auditor.audit()
        mock_unlink.assert_called_once()
