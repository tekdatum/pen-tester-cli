"""Tests for pentester.auditors.garak.GarakAuditor.

Design notes
------------
* garak is an external library not in pyproject.toml dependencies.  All
  garak.* modules are stubbed via sys.modules before the module under test is
  imported so the suite runs without the real package present.
* All pentester.* internal imports resolve normally (pydantic-settings is
  installed in the project's conda environment).
* Settings are injected via GarakAuditor(settings=GarakSettings(...)) so no
  module-level patching of get_settings() is needed in any test.
"""

from __future__ import annotations

import argparse
import sys
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

for _name, _stub in [
    ("garak", _garak_mod),
    ("garak._config", _garak_config_mod),
    ("garak._plugins", _garak_plugins_mod),
    ("garak.command", _garak_command_mod),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.garak import GarakAuditor  # noqa: E402
from pentester.config.auditors.garak_settings import GarakSettings  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor(settings: GarakSettings | None = None) -> GarakAuditor:
    return GarakAuditor(settings=settings or GarakSettings())


# ---------------------------------------------------------------------------
# _get_all_active_probes
# ---------------------------------------------------------------------------


class TestGetAllActiveProbes:
    def test_returns_only_active_probe_names(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", True),
            ("probes.dan.Dan2", False),
            ("probes.xss.Xss1", True),
        ]
        assert _make_auditor()._get_all_active_probes() == [
            "probes.dan.Dan1",
            "probes.xss.Xss1",
        ]

    def test_excludes_all_inactive_probes(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", False),
            ("probes.dan.Dan2", False),
        ]
        assert _make_auditor()._get_all_active_probes() == []

    def test_empty_plugin_list_returns_empty(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = []
        assert _make_auditor()._get_all_active_probes() == []

    def test_calls_enumerate_plugins_with_probes_category(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = []
        _make_auditor()._get_all_active_probes()
        _garak_plugins_mod.enumerate_plugins.assert_called_with(category="probes")


# ---------------------------------------------------------------------------
# _init_garak
# ---------------------------------------------------------------------------


class TestInitGarak:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_config_mod.reset_mock()
        _garak_command_mod.reset_mock()
        self.auditor = _make_auditor(GarakSettings(generations=3, seed=99))

    def test_calls_load_base_config(self) -> None:
        self.auditor._init_garak()
        _garak_config_mod.load_base_config.assert_called_once()

    def test_sets_generations_from_settings(self) -> None:
        self.auditor._init_garak()
        assert _garak_config_mod.run.generations == 3

    def test_sets_seed_from_settings(self) -> None:
        self.auditor._init_garak()
        assert _garak_config_mod.run.seed == 99

    def test_sets_interactive_to_false(self) -> None:
        self.auditor._init_garak()
        assert _garak_config_mod.run.interactive is False

    def test_cli_args_is_argparse_namespace(self) -> None:
        self.auditor._init_garak()
        assert isinstance(_garak_config_mod.transient.cli_args, argparse.Namespace)

    def test_cli_args_probes_is_none(self) -> None:
        self.auditor._init_garak()
        assert _garak_config_mod.transient.cli_args.probes is None

    def test_cli_args_all_list_flags_false(self) -> None:
        self.auditor._init_garak()
        ns = _garak_config_mod.transient.cli_args
        assert ns.list_probes is False
        assert ns.list_detectors is False
        assert ns.list_generators is False
        assert ns.list_buffs is False
        assert ns.list_config is False
        assert ns.plugin_info is False

    def test_sets_starttime_when_falsy(self) -> None:
        _garak_config_mod.transient.starttime = None
        self.auditor._init_garak()
        assert _garak_config_mod.transient.starttime is not None

    def test_sets_starttime_iso_when_falsy(self) -> None:
        _garak_config_mod.transient.starttime = None
        self.auditor._init_garak()
        assert _garak_config_mod.transient.starttime_iso is not None

    def test_does_not_overwrite_existing_starttime(self) -> None:
        existing = MagicMock()  # truthy
        _garak_config_mod.transient.starttime = existing
        self.auditor._init_garak()
        assert _garak_config_mod.transient.starttime is existing

    def test_calls_start_run(self) -> None:
        self.auditor._init_garak()
        _garak_command_mod.start_run.assert_called_once()


# ---------------------------------------------------------------------------
# _load_probes
# ---------------------------------------------------------------------------


class TestLoadProbes:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_plugins_mod.load_plugin.reset_mock(side_effect=True, return_value=True)
        _garak_plugins_mod.enumerate_plugins.reset_mock(side_effect=True, return_value=True)
        _garak_plugins_mod.enumerate_plugins.return_value = []

    @staticmethod
    def _run(probes: list[str]) -> list:
        return _make_auditor(GarakSettings(probes=probes))._load_probes()

    # probe-source selection ------------------------------------------------

    def test_calls_get_all_active_when_probes_empty(self) -> None:
        auditor = _make_auditor(GarakSettings(probes=[]))
        with patch.object(auditor, "_get_all_active_probes", return_value=[]) as m:
            auditor._load_probes()
        m.assert_called_once()

    def test_uses_settings_probes_when_non_empty(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [("probes.dan.Dan1", True)]
        _garak_plugins_mod.load_plugin.return_value = MagicMock()
        assert len(self._run(["probes.dan"])) == 1

    # two-part name (category.module) ----------------------------------------

    def test_two_part_name_loads_all_matching_plugins(self) -> None:
        p1, p2 = MagicMock(), MagicMock()
        _garak_plugins_mod.enumerate_plugins.return_value = [
            ("probes.dan.Dan1", True),
            ("probes.dan.Dan2", True),
        ]
        _garak_plugins_mod.load_plugin.side_effect = [p1, p2]
        assert self._run(["probes.dan"]) == [p1, p2]

    def test_two_part_name_passes_category_to_enumerate(self) -> None:
        self._run(["probes.dan"])
        _garak_plugins_mod.enumerate_plugins.assert_called_once_with("probes")

    def test_two_part_name_skips_plugins_from_other_modules(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [("probes.xss.Xss1", True)]
        result = self._run(["probes.dan"])
        _garak_plugins_mod.load_plugin.assert_not_called()
        assert result == []

    def test_two_part_name_passes_full_plugin_path_to_load(self) -> None:
        _garak_plugins_mod.enumerate_plugins.return_value = [("probes.dan.Dan1", True)]
        _garak_plugins_mod.load_plugin.return_value = MagicMock()
        self._run(["probes.dan"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("probes.dan.Dan1")

    # non-two-part name (direct load) ----------------------------------------

    def test_three_part_name_loads_plugin_directly(self) -> None:
        mock_plugin = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_plugin
        result = self._run(["probes.dan.Dan1"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("probes.dan.Dan1")
        assert result == [mock_plugin]

    def test_single_part_name_loads_plugin_directly(self) -> None:
        mock_plugin = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_plugin
        result = self._run(["someprobe"])
        _garak_plugins_mod.load_plugin.assert_called_once_with("someprobe")
        assert result == [mock_plugin]

    # exception handling -----------------------------------------------------

    def test_exception_prints_skip_message(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _garak_plugins_mod.load_plugin.side_effect = RuntimeError("load failed")
        self._run(["bad.probe.Fails"])
        assert "Skipping bad.probe.Fails" in capsys.readouterr().out

    def test_exception_continues_loading_subsequent_probes(self) -> None:
        good_probe = MagicMock()
        _garak_plugins_mod.load_plugin.side_effect = [RuntimeError("bad"), good_probe]
        result = self._run(["bad.probe.Bad", "good.probe.Good"])
        assert result == [good_probe]

    # return value -----------------------------------------------------------

    def test_returns_empty_list_when_no_probes(self) -> None:
        auditor = _make_auditor(GarakSettings(probes=[]))
        with patch.object(auditor, "_get_all_active_probes", return_value=[]):
            result = auditor._load_probes()
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

    def test_returns_empty_list(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]),
        ):
            result = auditor.audit()
        assert result == []
