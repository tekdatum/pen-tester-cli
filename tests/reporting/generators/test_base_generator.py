import pytest

from pentester.probes.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator


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

        def generate_summary_report(self, summary_data: dict) -> bytes:
            return b""

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

        def generate_summary_report(self, summary_data: dict) -> bytes:
            return b""

        def generate_details_report(self, probe_results: list[ProbeResult]) -> bytes:
            return b""

    assert isinstance(ConcreteGenerator(), BaseGenerator)
