import pytest

from pentester.auditors.models.base_auditor import BaseAuditor
from pentester.auditors.models.probe_result import ProbeResult


def _make_result(**kwargs) -> ProbeResult:
    defaults = {
        "auditor": "injector",
        "attack_category": "prompt",
        "attack_type": "injection",
        "prompt": "Ignore previous instructions.",
        "response": "Access denied.",
        "bypassed": False,
        "score": 0.0,
    }
    return ProbeResult(**{**defaults, **kwargs})


class ConcreteAuditor(BaseAuditor):
    def __init__(self, results: list[ProbeResult]) -> None:
        super().__init__()
        self._results = results

    def audit(self) -> list[ProbeResult]:
        return self._results


def test_cannot_instantiate_abstract_class() -> None:
    with pytest.raises(TypeError):
        BaseAuditor()  # type: ignore[abstract]


def test_concrete_subclass_can_instantiate() -> None:
    auditor = ConcreteAuditor([])
    assert isinstance(auditor, BaseAuditor)


def test_audit_returns_empty_list() -> None:
    auditor = ConcreteAuditor([])
    assert auditor.audit() == []


def test_audit_returns_probe_results() -> None:
    results = [_make_result(), _make_result(auditor="other", bypassed=True)]
    auditor = ConcreteAuditor(results)
    assert auditor.audit() == results


def test_audit_return_type_is_list() -> None:
    auditor = ConcreteAuditor([_make_result()])
    assert isinstance(auditor.audit(), list)
