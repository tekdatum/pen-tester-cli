import pytest

from pentester.auditors.models.audit_result import AuditResult
from pentester.auditors.models.probe_result import ProbeResult
from pentester.enums.auditor_key import AuditorKey
from pentester.reporting.models.summary_result import SummaryResult
from pentester.reporting.utils.summary import Summarizer


def _probe(
    auditor: str = "garak",
    attack_category: str = "injection",
    attack_type: str = "direct",
    bypassed: bool = False,
    score: float = 0.0,
    metadata: dict | None = None,
) -> ProbeResult:
    return ProbeResult(
        auditor=auditor,
        attack_category=attack_category,
        attack_type=attack_type,
        prompt="Ignore previous instructions.",
        response="Access denied.",
        bypassed=bypassed,
        score=score,
        metadata=metadata or {},
    )


def _audit(*probes: ProbeResult, duration: float = 0.0) -> AuditResult:
    return AuditResult(
        auditor_key=AuditorKey.GARAK, duration=duration, results=list(probes)
    )


# --- summarize ---


def test_summarize_empty_returns_zero_result() -> None:
    result = Summarizer.summarize([])
    assert result == SummaryResult(total_probes=0, total_bypassed=0, success_rate=0.0)


def test_summarize_all_blocked() -> None:
    ar = _audit(_probe(bypassed=False), _probe(bypassed=False))
    result = Summarizer.summarize([ar])
    assert result.total_probes == 2
    assert result.total_bypassed == 0
    assert result.success_rate == 100.0


def test_summarize_all_bypassed() -> None:
    ar = _audit(_probe(bypassed=True), _probe(bypassed=True))
    result = Summarizer.summarize([ar])
    assert result.total_probes == 2
    assert result.total_bypassed == 2
    assert result.success_rate == 0.0


def test_summarize_mixed() -> None:
    ar = _audit(_probe(bypassed=True), _probe(bypassed=False), _probe(bypassed=False))
    result = Summarizer.summarize([ar])
    assert result.total_probes == 3
    assert result.total_bypassed == 1
    assert result.success_rate == pytest.approx(66.67, abs=0.01)


def test_summarize_returns_summary_result_instance() -> None:
    assert isinstance(Summarizer.summarize([_audit(_probe())]), SummaryResult)


def test_summarize_average_duration_is_total_duration_over_total_probes() -> None:
    ar_a = _audit(_probe(), _probe(), duration=4.0)
    ar_b = _audit(_probe(), duration=2.0)
    result = Summarizer.summarize([ar_a, ar_b])
    # total_duration=6.0, total_probes=3 → average=2.0
    assert result.average_duration == pytest.approx(2.0)


def test_summarize_average_duration_is_zero_when_empty() -> None:
    assert Summarizer.summarize([]).average_duration == 0.0


# --- summarize_by_auditor ---


def test_summarize_by_auditor_empty_results_returns_zero_result() -> None:
    ar = AuditResult(auditor_key=AuditorKey.GARAK, duration=0.0, results=[])
    result = Summarizer.summarize_by_auditor(ar)
    assert result == SummaryResult(total_probes=0, total_bypassed=0, success_rate=0.0)


def test_summarize_by_auditor_counts_probes() -> None:
    ar = _audit(_probe(bypassed=True), _probe(bypassed=False), duration=0.0)
    result = Summarizer.summarize_by_auditor(ar)
    assert result.total_probes == 2
    assert result.total_bypassed == 1


def test_summarize_by_auditor_returns_summary_result() -> None:
    ar = _audit(_probe(), duration=0.0)
    assert isinstance(Summarizer.summarize_by_auditor(ar), SummaryResult)


def test_summarize_by_auditor_average_duration_is_duration_over_probe_count() -> None:
    ar = _audit(_probe(), _probe(), duration=6.0)
    result = Summarizer.summarize_by_auditor(ar)
    assert result.average_duration == pytest.approx(3.0)


def test_summarize_by_auditor_counts_errors() -> None:
    ar = _audit(
        _probe(auditor="garak", metadata={"error": "HTTP 422"}),
        _probe(auditor="garak", bypassed=False),
        duration=0.0,
    )
    result = Summarizer.summarize_by_auditor(ar)
    assert result.total_errors == 1


# --- summarize_by_attack_category ---


def test_summarize_by_attack_category_empty_returns_empty_dict() -> None:
    assert Summarizer.summarize_by_attack_category([]) == {}


def test_summarize_by_attack_category_groups_correctly() -> None:
    data = [
        _probe(attack_category="jailbreak", bypassed=True),
        _probe(attack_category="jailbreak", bypassed=False),
        _probe(attack_category="prompt_injection", bypassed=False),
    ]
    result = Summarizer.summarize_by_attack_category(data)
    assert set(result.keys()) == {"jailbreak", "prompt_injection"}
    assert result["jailbreak"].total_probes == 2
    assert result["prompt_injection"].total_probes == 1


# --- summarize_by_attack_type ---


def test_summarize_by_attack_type_empty_returns_empty_dict() -> None:
    assert Summarizer.summarize_by_attack_type([]) == {}


def test_summarize_by_attack_type_groups_correctly() -> None:
    data = [
        _probe(attack_type="dan", bypassed=True),
        _probe(attack_type="dan", bypassed=True),
        _probe(attack_type="gcg", bypassed=False),
    ]
    result = Summarizer.summarize_by_attack_type(data)
    assert result["dan"].total_bypassed == 2
    assert result["gcg"].total_bypassed == 0


# --- filter_by_auditor ---


def test_filter_by_auditor_returns_matching_results() -> None:
    data = [_probe(auditor="garak"), _probe(auditor="pyrit"), _probe(auditor="garak")]
    result = Summarizer.filter_by_auditor("garak", data)
    assert len(result) == 2
    assert all(r.auditor == "garak" for r in result)


def test_filter_by_auditor_no_match_returns_empty() -> None:
    data = [_probe(auditor="garak")]
    assert Summarizer.filter_by_auditor("pyrit", data) == []


def test_filter_by_auditor_empty_data_returns_empty() -> None:
    assert Summarizer.filter_by_auditor("garak", []) == []


# --- unique_auditors ---


def test_unique_auditors_empty_returns_empty_list() -> None:
    assert Summarizer.unique_auditors([]) == []


def test_unique_auditors_returns_sorted_unique_values() -> None:
    data = [
        _probe(auditor="pyrit"),
        _probe(auditor="garak"),
        _probe(auditor="garak"),
    ]
    result = Summarizer.unique_auditors(data)
    assert result == ["garak", "pyrit"]


def test_unique_auditors_single_auditor() -> None:
    data = [_probe(auditor="garak"), _probe(auditor="garak")]
    assert Summarizer.unique_auditors(data) == ["garak"]


# --- error counting ---


def test_summary_counts_errors() -> None:
    ar = _audit(
        _probe(bypassed=False),
        _probe(bypassed=True),
        _probe(metadata={"error": "HTTP 422"}),
        _probe(metadata={"error": "script not found"}),
    )
    result = Summarizer.summarize([ar])
    assert result.total_errors == 2


def test_success_rate_excludes_errors_from_denominator() -> None:
    ar = _audit(
        _probe(bypassed=False),
        _probe(bypassed=True),
        _probe(bypassed=True),
        _probe(metadata={"error": "HTTP 422"}),
        _probe(metadata={"error": "script not found"}),
    )
    result = Summarizer.summarize([ar])
    # valid=3 (5 total - 2 errors), bypassed=2 → success_rate = (3-2)/3 * 100 ≈ 33.33
    assert result.success_rate == pytest.approx(33.33, abs=0.01)


def test_success_rate_is_zero_when_all_probes_errored() -> None:
    ar = _audit(
        _probe(metadata={"error": "HTTP 422"}),
        _probe(metadata={"error": "HTTP 422"}),
        _probe(metadata={"error": "script not found"}),
    )
    result = Summarizer.summarize([ar])
    assert result.success_rate == 0.0
