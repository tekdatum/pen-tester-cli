"""Tests for pentester.auditors.garak.GarakAuditor.

Design notes
------------
* garak is an optional external library not listed in pyproject.toml.  All
  garak.* modules are stubbed out via sys.modules *before* the module under
  test is imported, so the test suite runs without the real package present.
* garak.py uses un-prefixed import paths ("config.settings", "auditors.models…")
  rather than the pentester.* prefix.  Those modules are also stubbed out.
"""

from __future__ import annotations

import argparse
import sys
from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Register sys.modules stubs BEFORE importing the module under test.
# ---------------------------------------------------------------------------

_garak_config_mod = MagicMock(name="garak._config")
_garak_plugins_mod = MagicMock(name="garak._plugins")
_garak_command_mod = MagicMock(name="garak.command")
_garak_mod = MagicMock(name="garak")
_garak_mod._config = _garak_config_mod
_garak_mod._plugins = _garak_plugins_mod
_garak_mod.command = _garak_command_mod


class _BaseAuditor(ABC):
    """Minimal stand-in matching the real BaseAuditor's interface."""

    def __init__(self) -> None:
        pass

    @abstractmethod
    def audit(self): ...


_base_auditor_mod = MagicMock()
_base_auditor_mod.BaseAuditor = _BaseAuditor

_probe_result_mod = MagicMock()

for _name, _stub in [
    ("garak", _garak_mod),
    ("garak._config", _garak_config_mod),
    ("garak._plugins", _garak_plugins_mod),
    ("garak.command", _garak_command_mod),
    ("config", MagicMock(name="config")),
    ("config.settings", MagicMock(name="config.settings")),
    ("auditors", MagicMock(name="auditors")),
    ("auditors.models", MagicMock(name="auditors.models")),
    ("auditors.models.base_auditor", _base_auditor_mod),
    ("auditors.models.probe_result", _probe_result_mod),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.garak import GarakAuditor  # noqa: E402
import pentester.auditors.garak as _garak_module  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor() -> GarakAuditor:
    return GarakAuditor()


def _fake_settings(
    *, probes: list[str] | None = None, generations: int = 1, seed: int = 42
) -> MagicMock:
    s = MagicMock()
    s.garak.probes = probes or []
    s.garak.generations = generations
    s.garak.seed = seed
    return s


# ---------------------------------------------------------------------------
# _get_all_active_probes  — class-level function (no self in source)
# ---------------------------------------------------------------------------


class TestGetAllActiveProbes:
    def test_returns_only_active_probe_names(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", True),
            ("probes.dan.Dan2", False),
            ("probes.xss.Xss1", True),
        ]
        result = GarakAuditor._get_all_active_probes()
        assert result == ["probes.dan.Dan1", "probes.xss.Xss1"]

    def test_excludes_all_inactive_probes(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", False),
            ("probes.dan.Dan2", False),
        ]
        result = GarakAuditor._get_all_active_probes()
        assert result == []

    def test_empty_plugin_list_returns_empty(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = []
        result = GarakAuditor._get_all_active_probes()
        assert result == []

    def test_calls_enumerate_plugins_with_probes_category(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = []
        GarakAuditor._get_all_active_probes()
        _garak_plugins_mod.enumerate_plugins.assert_called_with(category="probes")


# ---------------------------------------------------------------------------
# _init_garak
# ---------------------------------------------------------------------------


class TestInitGarak:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_config_mod.reset_mock()
        _garak_command_mod.reset_mock()
        settings = _fake_settings(generations=3, seed=99)
        with patch.object(_garak_module, "AuditorSettings", settings, create=True):
            yield

    def test_calls_load_base_config(self) -> None:
        _make_auditor()._init_garak()
        _garak_config_mod.load_base_config.assert_called_once()

    def test_sets_generations_from_settings(self) -> None:
        _make_auditor()._init_garak()
        assert _garak_config_mod.run.generations == 3

    def test_sets_seed_from_settings(self) -> None:
        _make_auditor()._init_garak()
        assert _garak_config_mod.run.seed == 99

    def test_sets_interactive_to_false(self) -> None:
        _make_auditor()._init_garak()
        assert _garak_config_mod.run.interactive is False

    def test_cli_args_is_argparse_namespace(self) -> None:
        _make_auditor()._init_garak()
        assert isinstance(_garak_config_mod.transient.cli_args, argparse.Namespace)

    def test_cli_args_probes_is_none(self) -> None:
        _make_auditor()._init_garak()
        assert _garak_config_mod.transient.cli_args.probes is None

    def test_cli_args_all_list_flags_false(self) -> None:
        _make_auditor()._init_garak()
        ns = _garak_config_mod.transient.cli_args
        assert ns.list_probes is False
        assert ns.list_detectors is False
        assert ns.list_generators is False
        assert ns.list_buffs is False
        assert ns.list_config is False
        assert ns.plugin_info is False

    def test_sets_starttime_when_falsy(self) -> None:
        _garak_config_mod.transient.starttime = None
        _make_auditor()._init_garak()
        assert _garak_config_mod.transient.starttime is not None

    def test_sets_starttime_iso_when_falsy(self) -> None:
        _garak_config_mod.transient.starttime = None
        _make_auditor()._init_garak()
        assert _garak_config_mod.transient.starttime_iso is not None

    def test_does_not_overwrite_existing_starttime(self) -> None:
        existing = MagicMock()  # truthy
        _garak_config_mod.transient.starttime = existing
        _make_auditor()._init_garak()
        assert _garak_config_mod.transient.starttime is existing

    def test_calls_start_run(self) -> None:
        _make_auditor()._init_garak()
        _garak_command_mod.start_run.assert_called_once()


# ---------------------------------------------------------------------------
# _load_probes
# ---------------------------------------------------------------------------


class TestLoadProbes:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_plugins_mod.reset_mock()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run(auditor: GarakAuditor, probes: list[str]) -> list:
        with patch.object(_garak_module, "PentesterSettings") as mock_ps:
            mock_ps.garak.probes = probes
            return auditor._load_probes()

    # ------------------------------------------------------------------
    # probe source selection
    # ------------------------------------------------------------------

    def test_calls_get_all_active_when_probes_empty(self) -> None:
        auditor = _make_auditor()
        auditor.get_all_active_probes = MagicMock(return_value=[])
        self._run(auditor, [])
        auditor.get_all_active_probes.assert_called_once()

    def test_uses_settings_probes_when_non_empty(self) -> None:
        auditor = _make_auditor()
        _garak_plugins_mod.enumerate_plugins.return_value = [("probes.dan.Dan1", True)]
        _garak_plugins_mod.load_plugin.return_value = MagicMock()
        result = self._run(auditor, ["probes.dan"])
        assert len(result) == 1

    # ------------------------------------------------------------------
    # two-part name  (category.module)
    # ------------------------------------------------------------------

    def test_two_part_name_loads_all_matching_plugins(self) -> None:
        auditor = _make_auditor()
        p1, p2 = MagicMock(), MagicMock()
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", True),
            ("probes.dan.Dan2", True),
        ]
        _garak_plugins_mod.load_plugin.side_effect = [p1, p2]
        result = self._run(auditor, ["probes.dan"])
        assert result == [p1, p2]

    def test_two_part_name_passes_category_to_enumerate(self) -> None:
        auditor = _make_auditor()
        _garak_plugins_mod.enumerate_plugins.return_value = []
        self._run(auditor, ["probes.dan"])
        _garak_plugins_mod.enumerate_plugins.assert_called_once_with("probes")

    def test_two_part_name_skips_plugins_from_other_modules(self) -> None:
        auditor = _make_auditor()
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.xss.Xss1", True),  # probes.xss, not probes.dan
        ]
        result = self._run(auditor, ["probes.dan"])
        _garak_plugins_mod.load_plugin.assert_not_called()
        assert result == []

    def test_two_part_name_passes_full_plugin_path_to_load(self) -> None:
        auditor = _make_auditor()
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", True),
        ]
        _garak_plugins_mod.load_plugin.return_value = MagicMock()
        self._run(auditor, ["probes.dan"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("probes.dan.Dan1")

    # ------------------------------------------------------------------
    # non-two-part name  (direct load)
    # ------------------------------------------------------------------

    def test_three_part_name_loads_plugin_directly(self) -> None:
        auditor = _make_auditor()
        mock_plugin = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_plugin
        result = self._run(auditor, ["probes.dan.Dan1"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("probes.dan.Dan1")
        assert result == [mock_plugin]

    def test_single_part_name_loads_plugin_directly(self) -> None:
        auditor = _make_auditor()
        mock_plugin = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_plugin
        result = self._run(auditor, ["someprobe"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("someprobe")
        assert result == [mock_plugin]

    # ------------------------------------------------------------------
    # exception handling
    # ------------------------------------------------------------------

    def test_exception_skips_bad_probe_and_prints_message(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        auditor = _make_auditor()
        _garak_plugins_mod.load_plugin.side_effect = RuntimeError("load failed")
        self._run(auditor, ["bad.probe.Fails"])
        assert "Skipping bad.probe.Fails" in capsys.readouterr().out

    def test_exception_continues_loading_subsequent_probes(self) -> None:
        auditor = _make_auditor()
        good_probe = MagicMock()
        _garak_plugins_mod.load_plugin.side_effect = [
            RuntimeError("bad"),
            good_probe,
        ]
        result = self._run(auditor, ["bad.probe.Bad", "good.probe.Good"])
        assert result == [good_probe]

    # ------------------------------------------------------------------
    # return value
    # ------------------------------------------------------------------

    def test_returns_empty_list_when_no_probes(self) -> None:
        auditor = _make_auditor()
        auditor.get_all_active_probes = MagicMock(return_value=[])
        result = self._run(auditor, [])
        assert result == []


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAudit:
    def test_calls_init_garak(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak") as m_init,
            patch.object(auditor, "_load_probes", return_value=[]),
        ):
            auditor.audit()
        m_init.assert_called_once()

    def test_calls_load_probes(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]) as m_load,
        ):
            auditor.audit()
        m_load.assert_called_once()

    def test_prints_each_probe_name(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        auditor = _make_auditor()
        probe_a, probe_b = MagicMock(), MagicMock()
        probe_a.probename = "probes.dan.Dan1"
        probe_b.probename = "probes.encoding.Encoding1"
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[probe_a, probe_b]),
        ):
            auditor.audit()
        out = capsys.readouterr().out
        assert "probes.dan.Dan1" in out
        assert "probes.encoding.Encoding1" in out

    def test_no_output_for_empty_probe_list(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]),
        ):
            auditor.audit()
        assert "Probe:" not in capsys.readouterr().out

    def test_returns_none(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]),
        ):
            result = auditor.audit()
        assert result is None
