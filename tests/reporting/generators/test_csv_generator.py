from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.generators.csv_generator import CsvGenerator


def _probe() -> ProbeResult:
    return ProbeResult(
        tool_id="t-001",
        tool_name="injector",
        accepted=False,
        attack_type="injection",
        attack_category="prompt",
        prompt="Ignore previous instructions.",
    )


def test_is_instance_of_base_generator() -> None:
    assert isinstance(CsvGenerator(), BaseGenerator)


def test_generator_key() -> None:
    assert CsvGenerator().generator_key == GeneratorKey.CSV


def test_extension() -> None:
    assert CsvGenerator().extension == GeneratorExtension.CSV


def test_generate_summary_report_returns_bytes() -> None:
    result = CsvGenerator().generate_summary_report({"host": "10.0.0.1"})
    assert isinstance(result, bytes)


def test_generate_details_report_returns_bytes() -> None:
    result = CsvGenerator().generate_details_report([_probe()])
    assert isinstance(result, bytes)


def test_generate_details_report_accepts_empty_list() -> None:
    result = CsvGenerator().generate_details_report([])
    assert isinstance(result, bytes)
