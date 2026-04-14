"""Tests for pentester.auditors.inspect_ai.fence_scorer.FenceScorerAPI."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from pentester.auditors.inspect_ai.fence_scorer import FenceScorerAPI  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fence_api() -> FenceScorerAPI:
    return FenceScorerAPI()


def _make_state(messages: list[Any] | None = None, input_val: Any = "") -> MagicMock:
    state = MagicMock()
    state.messages = messages if messages is not None else []
    state.input = input_val
    return state


# ---------------------------------------------------------------------------
# TestFenceScorerAPI
# ---------------------------------------------------------------------------


class TestFenceScorerAPI:
    def test_score_returns_one_when_bypassed(self) -> None:
        api = _make_fence_api()
        state = _make_state()
        state.output.metadata = {"bypassed": True}
        result = asyncio.run(api.score(state, MagicMock()))
        assert result.value == 1.0

    def test_score_returns_zero_when_blocked(self) -> None:
        api = _make_fence_api()
        state = _make_state()
        state.output.metadata = {"bypassed": False}
        result = asyncio.run(api.score(state, MagicMock()))
        assert result.value == 0.0

    def test_score_returns_none_when_metadata_is_none(self) -> None:
        api = _make_fence_api()
        state = _make_state()
        state.output.metadata = None
        result = asyncio.run(api.score(state, MagicMock()))
        assert result is None

    def test_score_raises_output_error_when_bypassed_key_missing(self) -> None:
        api = _make_fence_api()
        state = _make_state()
        state.output.metadata = {"other_key": "value"}
        state.output.error = "content moderation refusal"
        try:
            asyncio.run(api.score(state, MagicMock()))
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert str(exc) == "content moderation refusal"

    def test_score_raises_fallback_message_when_bypassed_key_missing_and_no_output_error(self) -> None:
        api = _make_fence_api()
        state = _make_state()
        state.output.metadata = {}
        state.output.error = None
        try:
            asyncio.run(api.score(state, MagicMock()))
            assert False, "expected RuntimeError"
        except RuntimeError as exc:
            assert "bypassed key missing" in str(exc)

    def test_extract_prompt_from_state_uses_last_message_text(self) -> None:
        api = _make_fence_api()
        msg1 = MagicMock()
        msg1.text = "first"
        msg1.content = "first"
        msg2 = MagicMock()
        msg2.text = "last"
        msg2.content = "last"
        state = _make_state(messages=[msg1, msg2])
        assert api._extract_prompt_from_state(state) == "last"

    def test_extract_prompt_from_state_falls_back_to_input(self) -> None:
        api = _make_fence_api()
        msg = MagicMock()
        msg.text = ""
        msg.content = ""
        state = _make_state(messages=[msg], input_val="fallback prompt")
        assert api._extract_prompt_from_state(state) == "fallback prompt"

    def test_extract_prompt_from_state_empty_messages_returns_input(self) -> None:
        api = _make_fence_api()
        state = _make_state(messages=[], input_val="direct input")
        assert api._extract_prompt_from_state(state) == "direct input"

    def test_extract_prompt_from_state_non_string_input_returns_empty(self) -> None:
        api = _make_fence_api()
        state = _make_state(messages=[], input_val=42)
        assert api._extract_prompt_from_state(state) == ""
