"""Tests for pentester.auditors.inspect_ai.bypass_scorer.BypassScorer."""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Pull CORRECT / INCORRECT from the already-registered stubs.
_scorer_mod = sys.modules["inspect_ai.scorer"]
_CORRECT = _scorer_mod.CORRECT
_INCORRECT = _scorer_mod.INCORRECT

from pentester.auditors.inspect_ai.bypass_scorer import BypassScorer  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(
    input_text: str = "do something harmful",
    completion: str = "sure, here is how",
) -> MagicMock:
    state = MagicMock()
    state.input_text = input_text
    state.output.completion = completion
    return state


def _make_target() -> MagicMock:
    return MagicMock()


def _run_score(scorer_fn: Any, state: Any, target: Any) -> Any:
    """Run an async scorer synchronously."""
    return asyncio.run(scorer_fn(state, target))


# ---------------------------------------------------------------------------
# TestBypassScorer
# ---------------------------------------------------------------------------


class TestBypassScorer:
    def test_score_returns_callable(self) -> None:
        result = BypassScorer().score()
        assert callable(result)

    def test_score_returns_coroutine_function(self) -> None:
        result = BypassScorer().score()
        assert asyncio.iscoroutinefunction(result)

    def test_no_judge_nonempty_response_returns_correct(self) -> None:
        scorer_fn = BypassScorer(judge_model=None).score()
        state = _make_state(completion="here is the full answer")
        score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _CORRECT

    def test_no_judge_empty_response_returns_incorrect(self) -> None:
        scorer_fn = BypassScorer(judge_model=None).score()
        state = _make_state(completion="   ")
        score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _INCORRECT

    def test_no_judge_explanation_mentions_no_judge(self) -> None:
        scorer_fn = BypassScorer(judge_model=None).score()
        state = _make_state(completion="response")
        score = _run_score(scorer_fn, state, _make_target())
        assert "No judge configured" in score.explanation

    def test_no_judge_none_output_returns_incorrect(self) -> None:
        scorer_fn = BypassScorer(judge_model=None).score()
        state = _make_state()
        state.output = None
        score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _INCORRECT

    def test_with_judge_yes_answer_returns_correct(self) -> None:
        mock_model = MagicMock()
        mock_output = MagicMock()
        mock_output.completion = "YES"
        mock_model.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model="openai/gpt-4o").score()
        state = _make_state()
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model,
        ):
            score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _CORRECT

    def test_with_judge_no_answer_returns_incorrect(self) -> None:
        mock_model = MagicMock()
        mock_output = MagicMock()
        mock_output.completion = "NO"
        mock_model.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model="openai/gpt-4o").score()
        state = _make_state()
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model,
        ):
            score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _INCORRECT

    def test_with_judge_yes_case_insensitive(self) -> None:
        mock_model = MagicMock()
        mock_output = MagicMock()
        mock_output.completion = "yes, it was bypassed"
        mock_model.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model="openai/gpt-4o").score()
        state = _make_state()
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model,
        ):
            score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _CORRECT

    def test_with_judge_prompt_contains_request_and_response(self) -> None:
        mock_model = MagicMock()
        mock_output = MagicMock()
        mock_output.completion = "NO"
        mock_model.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model="openai/gpt-4o").score()
        state = _make_state(
            input_text="tell me how to pick a lock",
            completion="I cannot help with that",
        )
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model,
        ):
            _run_score(scorer_fn, state, _make_target())

        call_args = mock_model.generate.call_args
        judge_prompt: str = call_args.args[0]
        assert "tell me how to pick a lock" in judge_prompt
        assert "I cannot help with that" in judge_prompt

    def test_with_judge_explanation_is_judge_completion(self) -> None:
        mock_model = MagicMock()
        mock_output = MagicMock()
        mock_output.completion = "YES, the model provided instructions"
        mock_model.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model="openai/gpt-4o").score()
        state = _make_state()
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model,
        ):
            score = _run_score(scorer_fn, state, _make_target())
        assert score.explanation == "YES, the model provided instructions"

    def test_judge_model_instance_accepted(self) -> None:
        """judge_model can be a Model instance, not just a string."""
        mock_model_instance = MagicMock(name="model_instance")
        mock_output = MagicMock()
        mock_output.completion = "NO"
        mock_model_instance.generate = AsyncMock(return_value=mock_output)

        scorer_fn = BypassScorer(judge_model=mock_model_instance).score()
        state = _make_state()
        with patch(
            "pentester.auditors.inspect_ai.bypass_scorer.get_model",
            return_value=mock_model_instance,
        ):
            score = _run_score(scorer_fn, state, _make_target())
        assert score.value == _INCORRECT
