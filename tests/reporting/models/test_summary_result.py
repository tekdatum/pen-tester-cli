from pentester.reporting.models.summary_result import SummaryResult


class TestSummaryResultDefaults:
    def test_total_errors_defaults_to_zero(self) -> None:
        result = SummaryResult(total_probes=1, total_bypassed=0, success_rate=100.0)
        assert result.total_errors == 0


class TestSummaryResultInstantiation:
    def test_all_fields_set_correctly(self) -> None:
        result = SummaryResult(
            total_probes=10,
            total_bypassed=3,
            success_rate=70.0,
            total_errors=2,
        )
        assert result.total_probes == 10
        assert result.total_bypassed == 3
        assert result.success_rate == 70.0
        assert result.total_errors == 2

    def test_equality_semantics(self) -> None:
        a = SummaryResult(total_probes=5, total_bypassed=1, success_rate=80.0, total_errors=0)
        b = SummaryResult(total_probes=5, total_bypassed=1, success_rate=80.0, total_errors=0)
        assert a == b

    def test_inequality_on_different_values(self) -> None:
        a = SummaryResult(total_probes=5, total_bypassed=1, success_rate=80.0, total_errors=0)
        b = SummaryResult(total_probes=5, total_bypassed=2, success_rate=60.0, total_errors=1)
        assert a != b
