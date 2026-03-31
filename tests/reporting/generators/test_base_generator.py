import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.enum.generator_extension import GeneratorExtension
from pentester.reporting.enum.generator_key import GeneratorKey
from pentester.reporting.generators.base_generator import BaseGenerator
from pentester.reporting.models.summary_result import SummaryResult
from pentester.utils.timer import track_time


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

        def generate_detail_report(
            self,
            probe_results: list[ProbeResult],
            attack_category_results: dict[str, SummaryResult],
            attack_type_results: dict[str, SummaryResult],
        ) -> bytes:
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

        def generate_detail_report(
            self,
            probe_results: list[ProbeResult],
            attack_category_results: dict[str, SummaryResult],
            attack_type_results: dict[str, SummaryResult],
        ) -> bytes:
            return b""

        def generate_summary_report(
            self,
            overall_results: SummaryResult,
            auditor_results: dict[str, SummaryResult],
        ) -> bytes:
            return b""

    assert ConcreteGenerator().details_link_extension == GeneratorExtension.PDF


# ── track_time coverage ───────────────────────────────────────────────────────


def _make_summary() -> SummaryResult:
    return SummaryResult(total_probes=1, total_bypassed=0, success_rate=100.0)


class TimedConcreteGenerator(BaseGenerator):
    @property
    def generator_key(self) -> GeneratorKey:
        return GeneratorKey.CSV

    @property
    def extension(self) -> GeneratorExtension:
        return GeneratorExtension.CSV

    @track_time()
    def generate_detail_report(
        self,
        probe_results: list[ProbeResult],
        attack_category_results: dict[str, SummaryResult],
        attack_type_results: dict[str, SummaryResult],
    ) -> bytes:
        return b"detail"

    @track_time()
    def generate_summary_report(
        self,
        overall_results: SummaryResult,
        auditor_results: dict[str, SummaryResult],
    ) -> bytes:
        return b"summary"


class TestGenerateDetailReportTimer:
    def test_returns_tuple(self) -> None:
        output = TimedConcreteGenerator().generate_detail_report([], {}, {})
        assert isinstance(output, tuple)
        assert len(output) == 2

    def test_first_element_is_bytes(self) -> None:
        content, _ = TimedConcreteGenerator().generate_detail_report([], {}, {})
        assert content == b"detail"

    def test_duration_is_non_negative(self) -> None:
        _, duration = TimedConcreteGenerator().generate_detail_report([], {}, {})
        assert isinstance(duration, float)
        assert duration >= 0


class TestGenerateSummaryReportTimer:
    def test_returns_tuple(self) -> None:
        output = TimedConcreteGenerator().generate_summary_report(_make_summary(), {})
        assert isinstance(output, tuple)
        assert len(output) == 2

    def test_first_element_is_bytes(self) -> None:
        content, _ = TimedConcreteGenerator().generate_summary_report(
            _make_summary(), {}
        )
        assert content == b"summary"

    def test_duration_is_non_negative(self) -> None:
        _, duration = TimedConcreteGenerator().generate_summary_report(
            _make_summary(), {}
        )
        assert isinstance(duration, float)
        assert duration >= 0
