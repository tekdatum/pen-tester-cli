from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.generators.pdf_generator import PdfGenerator


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
    assert isinstance(PdfGenerator(), BaseGenerator)


def test_generator_key() -> None:
    assert PdfGenerator().generator_key == GeneratorKey.PDF


def test_extension() -> None:
    assert PdfGenerator().extension == GeneratorExtension.PDF


def test_generate_summary_report_returns_bytes() -> None:
    result = PdfGenerator().generate_summary_report({"host": "10.0.0.1"})
    assert isinstance(result, bytes)


def test_generate_details_report_returns_bytes() -> None:
    result = PdfGenerator().generate_details_report([_probe()])
    assert isinstance(result, bytes)


def test_generate_details_report_accepts_empty_list() -> None:
    result = PdfGenerator().generate_details_report([])
    assert isinstance(result, bytes)
