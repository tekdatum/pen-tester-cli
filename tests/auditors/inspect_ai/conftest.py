"""Shared sys.modules stubs for inspect_ai and inspect_evals.

Registered via pytest_configure so stubs are in place before any test
module in this package is imported.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# inspect_ai.model: ModelAPI must be a real class for ScannerModelAPI inheritance
# ---------------------------------------------------------------------------

_inspect_ai_model_mod = MagicMock(name="inspect_ai.model")


class _StubModelAPI:
    """Minimal real base class so ScannerModelAPI can inherit at import time."""

    def __init__(
        self,
        model_name: str = "",
        base_url: str | None = None,
        api_key: str | None = None,
        api_key_vars: list[str] = [],
        config: Any = None,
    ) -> None:
        self.model_name = model_name


_inspect_ai_model_mod.ModelAPI = _StubModelAPI
_inspect_ai_model_mod.GenerateConfig = MagicMock(return_value=None)

# ---------------------------------------------------------------------------
# inspect_ai.scorer: CORRECT/INCORRECT must be real strings;
#   Score must be a real class so .value is inspectable;
#   scorer() must pass through so the inner async function is returned
# ---------------------------------------------------------------------------

_inspect_ai_scorer_mod = MagicMock(name="inspect_ai.scorer")
CORRECT = "C"
INCORRECT = "I"
_inspect_ai_scorer_mod.CORRECT = CORRECT
_inspect_ai_scorer_mod.INCORRECT = INCORRECT


class _StubScore:
    def __init__(self, value: Any = None, explanation: str = "") -> None:
        self.value = value
        self.explanation = explanation


_inspect_ai_scorer_mod.Score = _StubScore


def _mock_scorer(**_kwargs: Any) -> Any:
    """Passthrough decorator: @scorer(metrics=[...])(fn) returns fn unchanged."""

    def _decorator(fn: Any) -> Any:
        return fn

    return _decorator


_inspect_ai_scorer_mod.scorer = _mock_scorer

# ---------------------------------------------------------------------------
# Remaining inspect_ai submodules
# ---------------------------------------------------------------------------

_inspect_ai_solver_mod = MagicMock(name="inspect_ai.solver")
_inspect_ai_solver_mod.TaskState = MagicMock

_inspect_ai_mod = MagicMock(name="inspect_ai")
_inspect_ai_log_mod = MagicMock(name="inspect_ai.log")

# ---------------------------------------------------------------------------
# inspect_evals submodules
# ---------------------------------------------------------------------------

_inspect_evals_mod = MagicMock(name="inspect_evals")
_inspect_evals_strong_reject_mod = MagicMock(name="inspect_evals.strong_reject")
_inspect_evals_b3_mod = MagicMock(name="inspect_evals.b3")
_inspect_evals_fortress_mod = MagicMock(name="inspect_evals.fortress")
_inspect_evals_agentharm_mod = MagicMock(name="inspect_evals.agentharm")
_inspect_evals_agentdojo_mod = MagicMock(name="inspect_evals.agentdojo")
_inspect_evals_make_me_pay_mod = MagicMock(name="inspect_evals.make_me_pay")
_inspect_evals_wmdp_mod = MagicMock(name="inspect_evals.wmdp")
_inspect_evals_makemesay_mod = MagicMock(name="inspect_evals.makemesay")
_inspect_evals_mind2web_sc_mod = MagicMock(name="inspect_evals.mind2web_sc")

_STUBS = [
    ("inspect_ai", _inspect_ai_mod),
    ("inspect_ai.model", _inspect_ai_model_mod),
    ("inspect_ai.log", _inspect_ai_log_mod),
    ("inspect_ai.scorer", _inspect_ai_scorer_mod),
    ("inspect_ai.solver", _inspect_ai_solver_mod),
    ("inspect_evals", _inspect_evals_mod),
    ("inspect_evals.strong_reject", _inspect_evals_strong_reject_mod),
    ("inspect_evals.b3", _inspect_evals_b3_mod),
    ("inspect_evals.fortress", _inspect_evals_fortress_mod),
    ("inspect_evals.agentharm", _inspect_evals_agentharm_mod),
    ("inspect_evals.agentdojo", _inspect_evals_agentdojo_mod),
    ("inspect_evals.make_me_pay", _inspect_evals_make_me_pay_mod),
    ("inspect_evals.wmdp", _inspect_evals_wmdp_mod),
    ("inspect_evals.makemesay", _inspect_evals_makemesay_mod),
    ("inspect_evals.mind2web_sc", _inspect_evals_mind2web_sc_mod),
]


def pytest_configure(config: Any) -> None:  # noqa: ARG001
    """Register inspect_ai / inspect_evals stubs before test modules are imported."""
    for name, stub in _STUBS:
        sys.modules.setdefault(name, stub)
