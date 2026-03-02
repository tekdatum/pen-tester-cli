from unittest.mock import ANY, MagicMock, patch

import pytest

from pentester.probes.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.generators.mako_generator import MakoGenerator, _TEMPLATES_DIR


def _probe() -> ProbeResult:
    return ProbeResult(
        tool_id="t-001",
        tool_name="injector",
        accepted=False,
        attack_type="injection",
        attack_category="prompt",
        prompt="Ignore previous instructions.",
    )


def _concrete(template_name: str = "template.html") -> MakoGenerator:
    class ConcreteMakoGenerator(MakoGenerator):
        @property
        def generator_key(self) -> GeneratorKey:
            return GeneratorKey.HTML

        @property
        def extension(self) -> GeneratorExtension:
            return GeneratorExtension.HTML

        @property
        def details_template_name(self) -> str:
            return template_name

        def generate_summary_report(self, summary_data: dict) -> bytes:
            return b""

    return ConcreteMakoGenerator()


def test_cannot_instantiate_abstract_class() -> None:
    with pytest.raises(TypeError):
        MakoGenerator()  # type: ignore[abstract]


def test_is_subclass_of_base_generator() -> None:
    assert issubclass(MakoGenerator, BaseGenerator)


def test_partial_implementation_cannot_instantiate() -> None:
    class PartialMakoGenerator(MakoGenerator):
        @property
        def generator_key(self) -> GeneratorKey:
            return GeneratorKey.HTML

        @property
        def extension(self) -> GeneratorExtension:
            return GeneratorExtension.HTML

        def generate_summary_report(self, summary_data: dict) -> bytes:
            return b""

    with pytest.raises(TypeError):
        PartialMakoGenerator()  # type: ignore[abstract]


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_details_report_returns_bytes(mock_template_cls: MagicMock) -> None:
    mock_template_cls.return_value.render.return_value = "<html></html>"

    result = _concrete().generate_details_report([_probe()])

    assert result == b"<html></html>"


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_details_report_accepts_empty_list(
    mock_template_cls: MagicMock,
) -> None:
    mock_template_cls.return_value.render.return_value = ""

    result = _concrete().generate_details_report([])

    assert isinstance(result, bytes)


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_details_report_resolves_template_name_against_templates_dir(
    mock_template_cls: MagicMock,
) -> None:
    mock_template_cls.return_value.render.return_value = ""

    _concrete("my_template.html").generate_details_report([])

    mock_template_cls.assert_called_once_with(
        filename=str(_TEMPLATES_DIR / "my_template.html")
    )


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_details_report_passes_probe_results_to_template(
    mock_template_cls: MagicMock,
) -> None:
    mock_template_cls.return_value.render.return_value = ""
    probes = [_probe()]

    _concrete().generate_details_report(probes)

    mock_template_cls.return_value.render.assert_called_once_with(
        results=probes, created_at=ANY
    )


@patch("pentester.reporting.generators.mako_generator.Template")
def test_generate_details_report_encodes_template_output(
    mock_template_cls: MagicMock,
) -> None:
    mock_template_cls.return_value.render.return_value = "hello world"

    result = _concrete().generate_details_report([_probe()])

    assert result == b"hello world"
