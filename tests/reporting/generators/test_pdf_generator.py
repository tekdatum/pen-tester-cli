from pentester.probes.models.probe_result import ProbeResult
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


def test_generate_summary_report_returns_none() -> None:
    result = PdfGenerator().generate_summary_report({"host": "10.0.0.1"}, "/tmp/out")
    assert result is None


def test_generate_details_report_returns_none() -> None:
    result = PdfGenerator().generate_details_report([_probe()], "/tmp/out")
    assert result is None


def test_generate_details_report_accepts_empty_list() -> None:
    result = PdfGenerator().generate_details_report([], "/tmp/out")
    assert result is None
