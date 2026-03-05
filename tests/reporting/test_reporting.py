from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from pentester.probes.models.probe_result import ProbeResult
from pentester.reporting.generators.generator_factory import GeneratorFactory
from pentester.reporting.reporting import Reporting


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    GeneratorFactory._instance = None
    yield
    GeneratorFactory._instance = None


def _probe() -> ProbeResult:
    return ProbeResult(
        tool_id="t-001",
        tool_name="injector",
        accepted=False,
        attack_type="injection",
        attack_category="prompt",
        prompt="Ignore previous instructions.",
    )


def test_init_creates_factory_instance() -> None:
    r = Reporting()
    assert isinstance(r.factory, GeneratorFactory)


def test_generate_summary_dispatches_to_all_selected_generators(mocker) -> None:
    mock_a = MagicMock()
    mock_b = MagicMock()
    mocker.patch.object(GeneratorFactory, "get_all", return_value=[mock_a, mock_b])

    data = {"host": "10.0.0.1"}
    Reporting().generate_summary(data, "/out", ["pdf", "csv"])

    mock_a.generate_summary_report.assert_called_once_with(data, "/out")
    mock_b.generate_summary_report.assert_called_once_with(data, "/out")


def test_generate_details_dispatches_to_all_selected_generators(mocker) -> None:
    mock_a = MagicMock()
    mock_b = MagicMock()
    mocker.patch.object(GeneratorFactory, "get_all", return_value=[mock_a, mock_b])

    probes = [_probe()]
    Reporting().generate_details(probes, "/out", ["pdf", "csv"])

    mock_a.generate_details_report.assert_called_once_with(probes, "/out")
    mock_b.generate_details_report.assert_called_once_with(probes, "/out")


def test_generate_summary_passes_keys_to_factory(mocker) -> None:
    mock_get_all = mocker.patch.object(GeneratorFactory, "get_all", return_value=[])
    Reporting().generate_summary({}, "/out", ["pdf", "html"])
    mock_get_all.assert_called_once_with(["pdf", "html"])


def test_generate_details_passes_keys_to_factory(mocker) -> None:
    mock_get_all = mocker.patch.object(GeneratorFactory, "get_all", return_value=[])
    Reporting().generate_details([], "/out", ["csv"])
    mock_get_all.assert_called_once_with(["csv"])


def test_generate_summary_empty_keys_calls_no_generators(mocker) -> None:
    mock_get_all = mocker.patch.object(GeneratorFactory, "get_all", return_value=[])
    Reporting().generate_summary({}, "/out", [])
    mock_get_all.assert_called_once_with([])


def test_generate_details_empty_keys_calls_no_generators(mocker) -> None:
    mock_get_all = mocker.patch.object(GeneratorFactory, "get_all", return_value=[])
    Reporting().generate_details([], "/out", [])
    mock_get_all.assert_called_once_with([])
