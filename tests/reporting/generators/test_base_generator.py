import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.models.summary_result import SummaryResult


def test_cannot_instantiate_abstract_class() -> None:
    with pytest.raises(TypeError):
        BaseGenerator()  # type: ignore[abstract]


def test_partial_implementation_cannot_instantiate() -> None:
    class PartialGenerator(BaseGenerator):
        @property
        def generator_key(self) -> GeneratorKey:
            return GeneratorKey.PDF

        @property
        def extension(self) -> GeneratorExtension:
            return GeneratorExtension.PDF

    with pytest.raises(TypeError):
        PartialGenerator()  # type: ignore[abstract]


def test_full_implementation_can_instantiate() -> None:
    class ConcreteGenerator(BaseGenerator):
        @property
        def generator_key(self) -> GeneratorKey:
            return GeneratorKey.PDF

        @property
        def extension(self) -> GeneratorExtension:
            return GeneratorExtension.PDF

        def generate_detail_report(self, probe_results: list[ProbeResult]) -> bytes:
            return b""

        def generate_summary_report(
            self,
            overall_results: SummaryResult,
            auditor_results: dict[str, SummaryResult],
        ) -> bytes:
            return b""

    assert isinstance(ConcreteGenerator(), BaseGenerator)


def test_details_link_extension_defaults_to_extension() -> None:
    class ConcreteGenerator(BaseGenerator):
        @property
        def generator_key(self) -> GeneratorKey:
            return GeneratorKey.PDF

        @property
        def extension(self) -> GeneratorExtension:
            return GeneratorExtension.PDF

        def generate_detail_report(self, probe_results: list[ProbeResult]) -> bytes:
            return b""

        def generate_summary_report(
            self,
            overall_results: SummaryResult,
            auditor_results: dict[str, SummaryResult],
        ) -> bytes:
            return b""

    assert ConcreteGenerator().details_link_extension == GeneratorExtension.PDF
