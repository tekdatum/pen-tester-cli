"""Tests for Orchestrator.

pentester.auditors.garak is stubbed via sys.modules so the suite runs without
the real garak package.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub our auditor module so garak internals never load.
# ---------------------------------------------------------------------------

for _mod in (
    "pentester.auditors.garak",
    "pyrit",
    "pyrit.datasets",
    "pyrit.executor",
    "pyrit.executor.attack",
    "pyrit.executor.attack.core",
    "pyrit.executor.attack.multi_turn",
    "pyrit.memory",
    "pyrit.models",
    "pyrit.models.attack_result",
    "pyrit.prompt_target",
    "pyrit.score",
    "pyrit.score.true_false",
    "pyrit.score.true_false.self_ask_true_false_scorer",
    "pyrit.setup",
    "tqdm",
):
    sys.modules.setdefault(_mod, MagicMock())

from pentester.auditors.auditor_factory import AuditorFactory  # noqa: E402
from pentester.auditors.models.probe_result import ProbeResult  # noqa: E402
from pentester.config.reporting import ReportingSettings  # noqa: E402
from pentester.config.settings import PentesterSettings  # noqa: E402
from pentester.orchestrator import Orchestrator  # noqa: E402
from pentester.reporting.reporting import Reporting  # noqa: E402


@pytest.fixture(autouse=True)
def _patch_promptfoo_auditor():
    """Mock PromptfooAuditor at the factory boundary so its __init__ never runs."""
    with patch("pentester.auditors.auditor_factory.PromptfooAuditor"):
        yield


def _make_settings(
    auditors: list[str] | None = None, **reporting_kwargs
) -> PentesterSettings:
    kwargs: dict = {"reporting": ReportingSettings(**reporting_kwargs)}
    if auditors is not None:
        kwargs["auditors"] = auditors
    return PentesterSettings(**kwargs)


def _make_probe_result() -> ProbeResult:
    return ProbeResult(
        auditor="test",
        attack_category="cat",
        attack_type="type",
        prompt="prompt",
        response="response",
        bypassed=False,
        score=1.0,
    )


# ---------------------------------------------------------------------------
# TestOrchestratorInit
# ---------------------------------------------------------------------------


class TestOrchestratorInit:
    def test_creates_auditor_factory(self) -> None:
        orch = Orchestrator(_make_settings())
        assert isinstance(orch._auditor_factory, AuditorFactory)

    def test_creates_reporting(self) -> None:
        orch = Orchestrator(_make_settings())
        assert isinstance(orch._reporting, Reporting)


# ---------------------------------------------------------------------------
# TestExecute
# ---------------------------------------------------------------------------


class TestExecute:
    def test_calls_get_available_auditors_when_no_settings_auditors(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ) as mock_available,
            patch.object(orch._reporting, "generate"),
        ):
            orch.execute()
            mock_available.assert_called_once()

    def test_uses_settings_auditors_when_present(self) -> None:
        orch = Orchestrator(_make_settings(auditors=["garak"]))
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors"
            ) as mock_available,
            patch.object(
                orch._auditor_factory, "get_auditors", return_value=[]
            ) as mock_get,
            patch.object(orch._reporting, "generate"),
        ):
            orch.execute()
            mock_available.assert_not_called()
            mock_get.assert_called_once_with(["garak"])


# ---------------------------------------------------------------------------
# TestRunAndReport
# ---------------------------------------------------------------------------


class TestRunAndReport:
    def test_preflight_called_when_scanner_present(self) -> None:
        orch = Orchestrator(_make_settings())
        mock_scanner = MagicMock()
        mock_auditor = MagicMock()
        mock_auditor.audit_n_track.return_value = MagicMock(results=[])
        with (
            patch.object(
                type(orch._auditor_factory),
                "scanner",
                new_callable=PropertyMock,
                return_value=mock_scanner,
            ),
            patch.object(orch._reporting, "generate"),
        ):
            orch._run_and_report([mock_auditor])
            mock_scanner.preflight.assert_called_once()

    def test_preflight_skipped_when_no_scanner(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                type(orch._auditor_factory),
                "scanner",
                new_callable=PropertyMock,
                return_value=None,
            ),
            patch.object(orch._reporting, "generate"),
        ):
            orch._run_and_report([])  # must not raise

    def test_auditors_not_run_if_preflight_raises(self) -> None:
        orch = Orchestrator(_make_settings())
        mock_scanner = MagicMock()
        mock_scanner.preflight.side_effect = RuntimeError("fail")
        mock_auditor = MagicMock()
        with (
            patch.object(
                type(orch._auditor_factory),
                "scanner",
                new_callable=PropertyMock,
                return_value=mock_scanner,
            ),
            patch.object(orch._reporting, "generate"),
        ):
            with pytest.raises(RuntimeError):
                orch._run_and_report([mock_auditor])
            mock_auditor.audit_n_track.assert_not_called()

    def test_calls_audit_n_track_on_each_auditor(self) -> None:
        orch = Orchestrator(_make_settings())
        auditor_a = MagicMock()
        auditor_a.audit_n_track.return_value = MagicMock(results=[])
        auditor_b = MagicMock()
        auditor_b.audit_n_track.return_value = MagicMock(results=[])
        with patch.object(orch._reporting, "generate"):
            orch._run_and_report([auditor_a, auditor_b])
            auditor_a.audit_n_track.assert_called_once()
            auditor_b.audit_n_track.assert_called_once()

    def test_passes_audit_results_to_generate(self) -> None:
        orch = Orchestrator(_make_settings())
        auditor_a = MagicMock()
        auditor_b = MagicMock()
        with patch.object(orch._reporting, "generate") as mock_generate:
            orch._run_and_report([auditor_a, auditor_b])
            called = mock_generate.call_args.kwargs["auditor_results"]
            assert auditor_a.audit_n_track.return_value in called
            assert auditor_b.audit_n_track.return_value in called

    def test_passes_output_dir_path_to_generate(self) -> None:
        orch = Orchestrator(_make_settings(output_dir_path="/tmp/out/"))
        with patch.object(orch._reporting, "generate") as mock_generate:
            orch._run_and_report([])
            assert mock_generate.call_args.kwargs["output_dir_path"] == "/tmp/out/"

    def test_passes_parsed_generator_keys_to_generate(self) -> None:
        orch = Orchestrator(_make_settings(generator_keys="pdf,csv"))
        with patch.object(orch._reporting, "generate") as mock_generate:
            orch._run_and_report([])
            assert mock_generate.call_args.kwargs["generator_keys"] == ["pdf", "csv"]

    def test_empty_auditors_calls_generate_with_empty_data(self) -> None:
        orch = Orchestrator(_make_settings())
        with patch.object(orch._reporting, "generate") as mock_generate:
            orch._run_and_report([])
            assert mock_generate.call_args.kwargs["auditor_results"] == []


# ── track_time coverage ───────────────────────────────────────────────────────


class TestExecuteTimer:
    def test_execute_returns_tuple(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate"),
        ):
            output = orch.execute()
            assert isinstance(output, tuple)
            assert len(output) == 2

    def test_execute_first_element_is_none(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate"),
        ):
            result, _ = orch.execute()
            assert result is None

    def test_execute_duration_is_non_negative(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate"),
        ):
            _, duration = orch.execute()
            assert isinstance(duration, float)
            assert duration >= 0
