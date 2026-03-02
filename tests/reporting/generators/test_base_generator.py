import pytest

from pentester.probes.models.probe_result import ProbeResult
from pentester.reporting.generators.base_generator import BaseGenerator


def test_cannot_instantiate_abstract_class() -> None:
    with pytest.raises(TypeError):
        BaseGenerator()  # type: ignore[abstract]


def test_partial_implementation_cannot_instantiate() -> None:
    class PartialGenerator(BaseGenerator):
        def generate_summary_report(
            self, summary_data: dict, output_path: str
        ) -> None:
            pass

    with pytest.raises(TypeError):
        PartialGenerator()  # type: ignore[abstract]


def test_full_implementation_can_instantiate() -> None:
    class ConcreteGenerator(BaseGenerator):
        def generate_summary_report(
            self, summary_data: dict, output_path: str
        ) -> None:
            pass

        def generate_details_report(
            self, data: list[ProbeResult], output_path: str
        ) -> None:
            pass

    gen = ConcreteGenerator()
    assert isinstance(gen, BaseGenerator)
