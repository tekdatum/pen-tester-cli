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
from pentester.auditors.models.probe_result import ProbeResult  # noqa: E402
from pentester.config.auditors.garak_settings import GarakSettings  # noqa: E402
from pentester.config.settings import TargetType  # noqa: E402
from pentester.scanners.scanner import Scanner  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor(settings: GarakSettings | None = None) -> GarakAuditor:
    return GarakAuditor(settings=settings or GarakSettings())


def _make_llm_auditor(settings: GarakSettings | None = None) -> GarakAuditor:
    auditor = _make_auditor(settings)
    auditor.target_type = TargetType.LLM
    return auditor


def _make_probe(probename: str, prompts: list[str]) -> MagicMock:
    probe = MagicMock()
    probe.probename = probename
    probe.prompts = prompts
    return probe


def _make_scan_result(
    response: str = "HTTP/1.1 200 OK\n\n{}",
    bypassed: bool | None = True,
    score: float | None = 0.9,
) -> MagicMock:
    result = MagicMock()
    result.response = response
    result.bypassed = bypassed
    result.score = score
    return result


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
# _init_scanner
# ---------------------------------------------------------------------------


class TestInitScanner:
    def test_returns_scanner_instance(self) -> None:
        assert isinstance(_make_auditor()._init_scanner(), Scanner)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAudit:
    @pytest.fixture(autouse=True)
    def _mock_scanner(self) -> MagicMock:
        self.mock_scanner = MagicMock()
        self.mock_scanner.scan.return_value = _make_scan_result()
        return self.mock_scanner

    def _audit_with(
        self, probes: list, scanner: MagicMock | None = None
    ) -> list[ProbeResult]:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=probes),
            patch.object(auditor, "_init_scanner", return_value=scanner or self.mock_scanner),
        ):
            return auditor.audit()

    # orchestration ----------------------------------------------------------

    def test_calls_init_garak(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak") as m_init,
            patch.object(auditor, "_load_probes", return_value=[]),
            patch.object(auditor, "_init_scanner", return_value=self.mock_scanner),
        ):
            auditor.audit()
        m_init.assert_called_once()

    def test_calls_load_probes(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]) as m_load,
            patch.object(auditor, "_init_scanner", return_value=self.mock_scanner),
        ):
            auditor.audit()
        m_load.assert_called_once()

    def test_calls_init_scanner(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]),
            patch.object(auditor, "_init_scanner", return_value=self.mock_scanner) as m_scanner,
        ):
            auditor.audit()
        m_scanner.assert_called_once()

    # result count -----------------------------------------------------------

    def test_returns_empty_list_when_no_probes(self) -> None:
        assert self._audit_with([]) == []

    def test_probe_with_no_prompts_yields_no_results(self) -> None:
        assert self._audit_with([_make_probe("probes.dan.Dan1", [])]) == []

    def test_returns_one_result_per_prompt(self) -> None:
        probe = _make_probe("probes.dan.Dan1", ["p1", "p2"])
        assert len(self._audit_with([probe])) == 2

    def test_multiple_probes_accumulate_results(self) -> None:
        probes = [
            _make_probe("probes.dan.Dan1", ["p1"]),
            _make_probe("probes.xss.Xss1", ["p2", "p3"]),
        ]
        assert len(self._audit_with(probes)) == 3

    # ProbeResult field mapping ----------------------------------------------

    def test_result_auditor_is_garak(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].auditor == "garak"

    def test_result_attack_category_from_probename(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].attack_category == "dan"

    def test_result_attack_type_from_probename(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].attack_type == "Dan1"

    def test_result_prompt_matches_probe_prompt(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["injected text"])])
        assert results[0].prompt == "injected text"

    def test_result_response_from_scanner(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(response="HTTP/1.1 200 OK\n\nbody")
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].response == "HTTP/1.1 200 OK\n\nbody"

    def test_result_bypassed_true_when_scanner_returns_true(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(bypassed=True)
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].bypassed is True

    def test_result_bypassed_false_when_scanner_returns_false(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(bypassed=False)
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].bypassed is False

    def test_result_score_from_scanner(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(score=0.75)
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].score == 0.75

    def test_result_score_none_when_scanner_returns_none(self) -> None:
        self.mock_scanner.scan.return_value = _make_scan_result(score=None)
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].score is None

    def test_scanner_called_with_each_prompt(self) -> None:
        probe = _make_probe("probes.dan.Dan1", ["first", "second"])
        self._audit_with([probe])
        calls = [c.args[0] for c in self.mock_scanner.scan.call_args_list]
        assert calls == ["first", "second"]

    def test_results_are_probe_result_instances(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert all(isinstance(r, ProbeResult) for r in results)


# ---------------------------------------------------------------------------
# _init_generator
# ---------------------------------------------------------------------------


class TestInitGenerator:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_plugins_mod.load_plugin.reset_mock(side_effect=True, return_value=True)

    def test_loads_plugin_from_settings(self) -> None:
        settings = GarakSettings(generator="generators.openai.OpenAIGenerator", model="gpt-4o")
        _make_llm_auditor(settings)._init_generator()
        _garak_plugins_mod.load_plugin.assert_called_once_with("generators.openai.OpenAIGenerator")

    def test_sets_model_name_on_generator(self) -> None:
        mock_gen = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_gen
        settings = GarakSettings(generator="generators.openai.OpenAIGenerator", model="gpt-4o")
        _make_llm_auditor(settings)._init_generator()
        assert mock_gen.name == "gpt-4o"

    def test_returns_generator_instance(self) -> None:
        mock_gen = MagicMock()
        _garak_plugins_mod.load_plugin.return_value = mock_gen
        result = _make_llm_auditor(GarakSettings(generator="generators.openai.OpenAIGenerator"))._init_generator()
        assert result is mock_gen


# ---------------------------------------------------------------------------
# _evaluate
# ---------------------------------------------------------------------------


class TestEvaluate:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:  # type: ignore[override]
        _garak_plugins_mod.load_plugin.reset_mock(side_effect=True, return_value=True)

    def _probe_with_detectors(self, detector_specs: list[str]) -> MagicMock:
        probe = MagicMock()
        probe.detector_specs = detector_specs
        return probe

    def test_returns_zero_when_no_detector_specs(self) -> None:
        probe = self._probe_with_detectors([])
        assert _make_llm_auditor()._evaluate(probe, "some response") == 0.0

    def test_returns_zero_when_detector_specs_missing(self) -> None:
        probe = MagicMock(spec=[])  # no detector_specs attribute
        assert _make_llm_auditor()._evaluate(probe, "some response") == 0.0

    def test_loads_each_detector_plugin(self) -> None:
        detector = MagicMock()
        detector.detect.return_value = [0.5]
        _garak_plugins_mod.load_plugin.return_value = detector
        probe = self._probe_with_detectors(["detectors.always.Fail", "detectors.always.Pass"])
        _make_llm_auditor()._evaluate(probe, "response")
        assert _garak_plugins_mod.load_plugin.call_count == 2

    def test_calls_detect_with_response_text(self) -> None:
        detector = MagicMock()
        detector.detect.return_value = [0.7]
        _garak_plugins_mod.load_plugin.return_value = detector
        probe = self._probe_with_detectors(["detectors.always.Fail"])
        _make_llm_auditor()._evaluate(probe, "attack response")
        detector.detect.assert_called_once_with("attack response")

    def test_returns_max_score_across_detectors(self) -> None:
        low, high = MagicMock(), MagicMock()
        low.detect.return_value = [0.2]
        high.detect.return_value = [0.9]
        _garak_plugins_mod.load_plugin.side_effect = [low, high]
        probe = self._probe_with_detectors(["detectors.a.Low", "detectors.a.High"])
        assert _make_llm_auditor()._evaluate(probe, "response") == 0.9

    def test_returns_max_across_multi_score_detector(self) -> None:
        detector = MagicMock()
        detector.detect.return_value = [0.1, 0.8, 0.4]
        _garak_plugins_mod.load_plugin.return_value = detector
        probe = self._probe_with_detectors(["detectors.always.Fail"])
        assert _make_llm_auditor()._evaluate(probe, "response") == 0.8

    def test_single_detector_single_score(self) -> None:
        detector = MagicMock()
        detector.detect.return_value = [0.6]
        _garak_plugins_mod.load_plugin.return_value = detector
        probe = self._probe_with_detectors(["detectors.always.Fail"])
        assert _make_llm_auditor()._evaluate(probe, "response") == 0.6


# ---------------------------------------------------------------------------
# audit — LLM path
# ---------------------------------------------------------------------------


class TestAuditLLM:
    @pytest.fixture(autouse=True)
    def _mock_generator(self) -> None:
        self.mock_generator = MagicMock()
        self.mock_generator.generate.return_value = ["LLM response text"]

    def _audit_with(self, probes: list, score: float = 0.8) -> list[ProbeResult]:
        auditor = _make_llm_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=probes),
            patch.object(auditor, "_init_generator", return_value=self.mock_generator),
            patch.object(auditor, "_evaluate", return_value=score),
        ):
            return auditor.audit()

    def test_calls_init_generator(self) -> None:
        auditor = _make_llm_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[]),
            patch.object(auditor, "_init_generator") as m_gen,
            patch.object(auditor, "_evaluate", return_value=0.0),
        ):
            auditor.audit()
        m_gen.assert_called_once()

    def test_returns_empty_when_no_probes(self) -> None:
        assert self._audit_with([]) == []

    def test_probe_with_no_prompts_yields_no_results(self) -> None:
        assert self._audit_with([_make_probe("probes.dan.Dan1", [])]) == []

    def test_returns_one_result_per_prompt(self) -> None:
        probe = _make_probe("probes.dan.Dan1", ["p1", "p2"])
        assert len(self._audit_with([probe])) == 2

    def test_generator_called_with_each_prompt(self) -> None:
        probe = _make_probe("probes.dan.Dan1", ["first", "second"])
        auditor = _make_llm_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[probe]),
            patch.object(auditor, "_init_generator", return_value=self.mock_generator),
            patch.object(auditor, "_evaluate", return_value=0.0),
        ):
            auditor.audit()
        calls = [c.args[0] for c in self.mock_generator.generate.call_args_list]
        assert calls == ["first", "second"]

    def test_evaluate_called_with_probe_and_response(self) -> None:
        probe = _make_probe("probes.dan.Dan1", ["p"])
        self.mock_generator.generate.return_value = ["the response"]
        auditor = _make_llm_auditor()
        with (
            patch.object(auditor, "_init_garak"),
            patch.object(auditor, "_load_probes", return_value=[probe]),
            patch.object(auditor, "_init_generator", return_value=self.mock_generator),
            patch.object(auditor, "_evaluate", return_value=0.0) as m_eval,
        ):
            auditor.audit()
        m_eval.assert_called_once_with(probe, "the response")

    def test_result_response_is_llm_text(self) -> None:
        self.mock_generator.generate.return_value = ["generated text"]
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].response == "generated text"

    def test_result_bypassed_true_when_score_above_threshold(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])], score=0.6)
        assert results[0].bypassed is True

    def test_result_bypassed_false_when_score_at_threshold(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])], score=0.5)
        assert results[0].bypassed is False

    def test_result_bypassed_false_when_score_below_threshold(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])], score=0.3)
        assert results[0].bypassed is False

    def test_result_score_from_evaluate(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])], score=0.75)
        assert results[0].score == 0.75

    def test_result_attack_category_from_probename(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].attack_category == "dan"

    def test_result_attack_type_from_probename(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert results[0].attack_type == "Dan1"

    def test_results_are_probe_result_instances(self) -> None:
        results = self._audit_with([_make_probe("probes.dan.Dan1", ["p"])])
        assert all(isinstance(r, ProbeResult) for r in results)
