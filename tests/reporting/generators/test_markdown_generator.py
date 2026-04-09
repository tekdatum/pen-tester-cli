from unittest.mock import MagicMock, patch

from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.generators.mako_generator import MakoGenerator
from pentester.reporting.generators.markdown_generator import MarkdownGenerator


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


def _error_probe(prompt: str = "error prompt") -> ProbeResult:
    return _probe(prompt=prompt, metadata={"error": "HTTP 422 error"})


def test_is_instance_of_base_generator() -> None:
    assert isinstance(MarkdownGenerator(), BaseGenerator)


def test_is_instance_of_mako_generator() -> None:
    assert isinstance(MarkdownGenerator(), MakoGenerator)


def test_generator_key() -> None:
    assert MarkdownGenerator().generator_key == GeneratorKey.MARKDOWN


def test_extension() -> None:
    assert MarkdownGenerator().extension == GeneratorExtension.MARKDOWN


def test_details_template_name_is_md_file() -> None:
    assert MarkdownGenerator().details_template_name == "details.md"


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_detail_report_returns_bytes(mock_template_cls: MagicMock) -> None:
    mock_template_cls.return_value.render.return_value = "# Report\n"

    result = MarkdownGenerator().generate_detail_report([_probe()], {}, {})

    assert result == b"# Report\n"


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_detail_report_accepts_empty_list(
    mock_template_cls: MagicMock,
) -> None:
    mock_template_cls.return_value.render.return_value = ""

    result = MarkdownGenerator().generate_detail_report([], {}, {})

    assert isinstance(result, bytes)


class TestDetailsTemplate:
    def test_bypassed_prompt_appears_in_bypassed_section(self) -> None:
        bypassed = _probe(bypassed=True, prompt="bypass me")
        md = MarkdownGenerator().generate_detail_report([bypassed], {}, {}).decode()
        bypassed_section, blocked_section = md.split("## Blocked Prompts")
        assert "bypass me" in bypassed_section

    def test_blocked_prompt_appears_in_blocked_section(self) -> None:
        blocked = _probe(bypassed=False, prompt="block me")
        md = MarkdownGenerator().generate_detail_report([blocked], {}, {}).decode()
        blocked_section = md.split("## Blocked Prompts")[1].split("## Error Prompts")[0]
        assert "block me" in blocked_section

    def test_bypassed_prompt_not_in_blocked_section(self) -> None:
        bypassed = _probe(bypassed=True, prompt="bypass only")
        md = MarkdownGenerator().generate_detail_report([bypassed], {}, {}).decode()
        blocked_section = md.split("## Blocked Prompts")[1].split("## Error Prompts")[0]
        assert "bypass only" not in blocked_section

    def test_blocked_prompt_not_in_bypassed_section(self) -> None:
        blocked = _probe(bypassed=False, prompt="block only")
        md = MarkdownGenerator().generate_detail_report([blocked], {}, {}).decode()
        bypassed_section, _ = md.split("## Blocked Prompts")
        assert "block only" not in bypassed_section

    def test_error_prompt_appears_in_error_section(self) -> None:
        error = _error_probe(prompt="error me")
        md = MarkdownGenerator().generate_detail_report([error], {}, {}).decode()
        _, error_section = md.split("## Error Prompts")
        assert "error me" in error_section
        assert "HTTP 422 error" in error_section

    def test_error_prompt_not_in_bypassed_section(self) -> None:
        error = _error_probe(prompt="error only")
        md = MarkdownGenerator().generate_detail_report([error], {}, {}).decode()
        bypassed_section = md.split("## Bypassed Prompts")[1].split(
            "## Blocked Prompts"
        )[0]
        assert "error only" not in bypassed_section

    def test_error_prompt_not_in_blocked_section(self) -> None:
        error = _error_probe(prompt="error only")
        md = MarkdownGenerator().generate_detail_report([error], {}, {}).decode()
        blocked_section = md.split("## Blocked Prompts")[1].split("## Error Prompts")[0]
        assert "error only" not in blocked_section

    def test_no_full_results_section(self) -> None:
        probe = _probe()
        md = MarkdownGenerator().generate_detail_report([probe], {}, {}).decode()
        assert "Results by Attack Category" not in md
        assert "Results by Attack Type" not in md

    def test_unicode_char_in_prompt_is_escaped(self) -> None:
        probe = _probe(bypassed=True, prompt="caf\u00e9")
        md = MarkdownGenerator().generate_detail_report([probe], {}, {}).decode()
        assert "\\xe9" in md

    def test_newline_in_prompt_is_escaped(self) -> None:
        probe = _probe(bypassed=True, prompt="line1\nline2")
        md = MarkdownGenerator().generate_detail_report([probe], {}, {}).decode()
        assert "\\n" in md
        assert "line1\nline2" not in md

    def test_judge_reason_column_header_present(self) -> None:
        probe = _probe()
        md = MarkdownGenerator().generate_detail_report([probe], {}, {}).decode()
        assert "Judge Reason" in md

    def test_judge_reason_appears_in_bypassed_section(self) -> None:
        bypassed = _probe(
            bypassed=True, metadata={"judge_reason": "response is harmful"}
        )
        md = MarkdownGenerator().generate_detail_report([bypassed], {}, {}).decode()
        bypassed_section = md.split("## Blocked Prompts")[0]
        assert "response is harmful" in bypassed_section

    def test_judge_reason_appears_in_blocked_section(self) -> None:
        blocked = _probe(
            bypassed=False, metadata={"judge_reason": "safe response detected"}
        )
        md = MarkdownGenerator().generate_detail_report([blocked], {}, {}).decode()
        blocked_section = md.split("## Blocked Prompts")[1].split("## Error Prompts")[0]
        assert "safe response detected" in blocked_section
