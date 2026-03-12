"""Tests for Orchestrator.

pentester.auditors.garak is stubbed via sys.modules so the suite runs without
the real garak package.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub our auditor module so garak internals never load.
# ---------------------------------------------------------------------------

sys.modules.setdefault("pentester.auditors.garak", MagicMock())

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


def _make_settings(**reporting_kwargs) -> PentesterSettings:
    return PentesterSettings(reporting=ReportingSettings(**reporting_kwargs))


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
    def test_calls_get_available_auditors(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ) as mock_auditors,
            patch.object(orch._reporting, "generate"),
        ):
            orch.execute()
            mock_auditors.assert_called_once()

    def test_calls_audit_on_each_auditor(self) -> None:
        orch = Orchestrator(_make_settings())
        auditor_a = MagicMock()
        auditor_a.audit.return_value = []
        auditor_b = MagicMock()
        auditor_b.audit.return_value = []
        with (
            patch.object(
                orch._auditor_factory,
                "get_available_auditors",
                return_value=[auditor_a, auditor_b],
            ),
            patch.object(orch._reporting, "generate"),
        ):
            orch.execute()
            auditor_a.audit.assert_called_once()
            auditor_b.audit.assert_called_once()

    def test_concatenates_probe_results(self) -> None:
        orch = Orchestrator(_make_settings())
        result_a = _make_probe_result()
        result_b = _make_probe_result()
        auditor_a = MagicMock()
        auditor_a.audit.return_value = [result_a]
        auditor_b = MagicMock()
        auditor_b.audit.return_value = [result_b]
        with (
            patch.object(
                orch._auditor_factory,
                "get_available_auditors",
                return_value=[auditor_a, auditor_b],
            ),
            patch.object(orch._reporting, "generate") as mock_generate,
        ):
            orch.execute()
            called_data = mock_generate.call_args.kwargs["data"]
            assert result_a in called_data
            assert result_b in called_data

    def test_passes_output_dir_path_to_generate(self) -> None:
        orch = Orchestrator(_make_settings(output_dir_path="/tmp/out/"))
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate") as mock_generate,
        ):
            orch.execute()
            assert mock_generate.call_args.kwargs["output_dir_path"] == "/tmp/out/"

    def test_passes_parsed_generator_keys_to_generate(self) -> None:
        orch = Orchestrator(_make_settings(generator_keys="pdf,csv"))
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate") as mock_generate,
        ):
            orch.execute()
            assert mock_generate.call_args.kwargs["generator_keys"] == ["pdf", "csv"]

    def test_empty_auditors_calls_generate_with_empty_list(self) -> None:
        orch = Orchestrator(_make_settings())
        with (
            patch.object(
                orch._auditor_factory, "get_available_auditors", return_value=[]
            ),
            patch.object(orch._reporting, "generate") as mock_generate,
        ):
            orch.execute()
            assert mock_generate.call_args.kwargs["data"] == []
