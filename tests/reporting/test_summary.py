import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.reporting.models.summary_result import SummaryResult
from pentester.reporting.utils.summary import Summarizer


def _probe(
    auditor: str = "garak",
    attack_category: str = "injection",
    attack_type: str = "direct",
    bypassed: bool = False,
    score: float = 0.0,
) -> ProbeResult:
    return ProbeResult(
        auditor=auditor,
        attack_category=attack_category,
        attack_type=attack_type,
        prompt="Ignore previous instructions.",
        response="Access denied.",
        bypassed=bypassed,
        score=score,
    )


# --- summarize ---


def test_summarize_empty_returns_zero_result() -> None:
    result = Summarizer.summarize([])
    assert result == SummaryResult(total_probes=0, total_bypassed=0, success_rate=0.0)


def test_summarize_all_blocked() -> None:
    data = [_probe(bypassed=False), _probe(bypassed=False)]
    result = Summarizer.summarize(data)
    assert result.total_probes == 2
    assert result.total_bypassed == 0
    assert result.success_rate == 100.0


def test_summarize_all_bypassed() -> None:
    data = [_probe(bypassed=True), _probe(bypassed=True)]
    result = Summarizer.summarize(data)
    assert result.total_probes == 2
    assert result.total_bypassed == 2
    assert result.success_rate == 0.0


def test_summarize_mixed() -> None:
    data = [_probe(bypassed=True), _probe(bypassed=False), _probe(bypassed=False)]
    result = Summarizer.summarize(data)
    assert result.total_probes == 3
    assert result.total_bypassed == 1
    assert result.success_rate == pytest.approx(66.67, abs=0.01)


def test_summarize_returns_summary_result_instance() -> None:
    assert isinstance(Summarizer.summarize([_probe()]), SummaryResult)


# --- summarize_by_auditor ---


def test_summarize_by_auditor_empty_returns_empty_dict() -> None:
    assert Summarizer.summarize_by_auditor([]) == {}


def test_summarize_by_auditor_groups_correctly() -> None:
    data = [
        _probe(auditor="garak", bypassed=True),
        _probe(auditor="garak", bypassed=False),
        _probe(auditor="pyrit", bypassed=False),
    ]
    result = Summarizer.summarize_by_auditor(data)
    assert set(result.keys()) == {"garak", "pyrit"}
    assert result["garak"].total_probes == 2
    assert result["garak"].total_bypassed == 1
    assert result["pyrit"].total_probes == 1
    assert result["pyrit"].total_bypassed == 0


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
