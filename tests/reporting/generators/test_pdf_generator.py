import datetime

from pentester.auditors.models.probe_result import ProbeResult
from pentester.enums.prompt_type import PromptType
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.generators.pdf_generator import PdfGenerator
from pentester.reporting.models.summary_result import SummaryResult


def _probe(
    bypassed: bool = False,
    prompt: str = "Ignore previous instructions.",
    metadata: dict | None = None,
) -> ProbeResult:
    return ProbeResult(
        auditor="injector",
        attack_category="prompt",
        attack_type="injection",
        prompt=prompt,
        response="Access denied.",
        bypassed=bypassed,
        score=0.0,
        metadata=metadata or {},
    )


def _summary(rate: float = 95.0) -> SummaryResult:
    return SummaryResult(
        total_probes=100,
        total_bypassed=3,
        total_errors=2,
        success_rate=rate,
        average_duration=0.123,
    )


def _auditor_results() -> dict[str, SummaryResult]:
    return {
        "garak": SummaryResult(
            total_probes=50,
            total_bypassed=2,
            total_errors=1,
            success_rate=96.0,
            average_duration=0.100,
        ),
        "pyrit": SummaryResult(
            total_probes=50,
            total_bypassed=1,
            total_errors=1,
            success_rate=98.0,
            average_duration=0.146,
        ),
    }


def test_is_instance_of_base_generator() -> None:
    assert isinstance(PdfGenerator(), BaseGenerator)


def test_generator_key() -> None:
    assert PdfGenerator().generator_key == GeneratorKey.PDF


def test_extension() -> None:
    assert PdfGenerator().extension == GeneratorExtension.PDF


def test_generate_detail_report_returns_bytes() -> None:
    result = PdfGenerator().generate_detail_report([_probe()], {}, {})
    assert isinstance(result, bytes)


def test_generate_detail_report_accepts_empty_list() -> None:
    result = PdfGenerator().generate_detail_report([], {}, {})
    assert isinstance(result, bytes)


class TestSummaryReport:
    def test_returns_bytes(self) -> None:
        result = PdfGenerator().generate_summary_report(_summary(), _auditor_results())
        assert isinstance(result, bytes)

    def test_contains_title(self) -> None:
        content = (
            PdfGenerator().generate_summary_report(_summary(), {}).decode("latin-1")
        )
        assert "AI Guardrail Assessment" in content

    def test_contains_date_year(self) -> None:
        content = (
            PdfGenerator().generate_summary_report(_summary(), {}).decode("latin-1")
        )
        assert str(datetime.date.today().year) in content

    def test_contains_total_probes_value(self) -> None:
        content = (
            PdfGenerator().generate_summary_report(_summary(), {}).decode("latin-1")
        )
        assert "100" in content

    def test_contains_total_bypassed_value(self) -> None:
        content = (
            PdfGenerator().generate_summary_report(_summary(), {}).decode("latin-1")
        )
        assert "3" in content

    def test_contains_success_rate(self) -> None:
        content = (
            PdfGenerator().generate_summary_report(_summary(), {}).decode("latin-1")
        )
        assert "95.00%" in content

    def test_contains_auditor_name_in_table(self) -> None:
        content = (
            PdfGenerator()
            .generate_summary_report(_summary(), _auditor_results())
            .decode("latin-1")
        )
        assert "garak" in content

    def test_contains_group_by_tool_heading(self) -> None:
        content = (
            PdfGenerator()
            .generate_summary_report(_summary(), _auditor_results())
            .decode("latin-1")
        )
        assert "Group by Tool" in content

    def test_accepts_empty_auditor_results(self) -> None:
        result = PdfGenerator().generate_summary_report(_summary(), {})
        assert isinstance(result, bytes)

    def test_high_success_rate_present(self) -> None:
        content = (
            PdfGenerator()
            .generate_summary_report(_summary(rate=85.0), {})
            .decode("latin-1")
        )
        assert "85.00%" in content

    def test_low_success_rate_present(self) -> None:
        content = (
            PdfGenerator()
            .generate_summary_report(_summary(rate=50.0), {})
            .decode("latin-1")
        )
        assert "50.00%" in content


class TestDetailReport:
    def test_returns_bytes(self) -> None:
        result = PdfGenerator().generate_detail_report([_probe()], {}, {})
        assert isinstance(result, bytes)

    def test_accepts_empty_list(self) -> None:
        result = PdfGenerator().generate_detail_report([], {}, {})
        assert isinstance(result, bytes)

    def test_contains_bypassed_section_heading(self) -> None:
        content = (
            PdfGenerator().generate_detail_report([_probe()], {}, {}).decode("latin-1")
        )
        assert "Bypassed Prompts" in content

    def test_contains_blocked_section_heading(self) -> None:
        content = (
            PdfGenerator().generate_detail_report([_probe()], {}, {}).decode("latin-1")
        )
        assert "Blocked Prompts" in content

    def test_contains_error_section_heading(self) -> None:
        content = (
            PdfGenerator().generate_detail_report([_probe()], {}, {}).decode("latin-1")
        )
        assert "Error Prompts" in content

    def test_bypassed_prompt_text_present(self) -> None:
        probe = _probe(bypassed=True, prompt="sentinel_bypass_xyz")
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert "sentinel_bypass_xyz" in content

    def test_blocked_prompt_text_present(self) -> None:
        probe = _probe(bypassed=False, prompt="sentinel_blocked_xyz")
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert "sentinel_blocked_xyz" in content

    def test_error_message_present(self) -> None:
        probe = _probe(
            bypassed=False,
            prompt="error_prompt",
            metadata={"error": "HTTP 422 error"},
        )
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert "HTTP 422 error" in content

    def test_auditor_name_in_title(self) -> None:
        probe = _probe()  # auditor="injector"
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert "injector" in content

    def test_unicode_prompt_escaped(self) -> None:
        probe = _probe(prompt="caf\u00e9")
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        # formatted_prompt uses unicode_escape, so \xe9 appears
        assert "\\xe9" in content

    def test_prompt_type_column_heading_present(self) -> None:
        content = (
            PdfGenerator().generate_detail_report([_probe()], {}, {}).decode("latin-1")
        )
        assert "Prompt Type" in content

    def test_prompt_type_single_value_present(self) -> None:
        probe = _probe()  # default prompt_type=PromptType.SINGLE
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert PromptType.SINGLE.value in content

    def test_prompt_type_multiturn_value_present(self) -> None:
        probe = ProbeResult(
            auditor="injector",
            attack_category="prompt",
            attack_type="injection",
            prompt="attack",
            response="response",
            bypassed=True,
            score=1.0,
            prompt_type=PromptType.MULTITURN,
        )
        content = (
            PdfGenerator().generate_detail_report([probe], {}, {}).decode("latin-1")
        )
        assert PromptType.MULTITURN.value in content
