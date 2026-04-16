"""Tests for pentester.auditors.pyrit.scanner_target.ScannerTarget."""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub pyrit before any local import resolves it.
# ---------------------------------------------------------------------------

_pyrit_models_mod = MagicMock(name="pyrit.models")
_pyrit_prompt_target_mod = MagicMock(name="pyrit.prompt_target")


class _FakePromptChatTarget:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self._memory = MagicMock()
        self._memory.get_conversation.return_value = []

    def get_identifier(self) -> dict:
        return {"id": "scanner"}


_pyrit_prompt_target_mod.PromptChatTarget = _FakePromptChatTarget

for _name, _stub in [
    ("pyrit", MagicMock(name="pyrit")),
    ("pyrit.models", _pyrit_models_mod),
    ("pyrit.prompt_target", _pyrit_prompt_target_mod),
    ("pyrit.datasets", MagicMock(name="pyrit.datasets")),
    ("pyrit.executor", MagicMock(name="pyrit.executor")),
    ("pyrit.executor.attack", MagicMock(name="pyrit.executor.attack")),
    ("pyrit.executor.attack.core", MagicMock(name="pyrit.executor.attack.core")),
    (
        "pyrit.executor.attack.multi_turn",
        MagicMock(name="pyrit.executor.attack.multi_turn"),
    ),
    ("pyrit.memory", MagicMock(name="pyrit.memory")),
    ("pyrit.setup", MagicMock(name="pyrit.setup")),
    ("pyrit.score", MagicMock(name="pyrit.score")),
    ("pyrit.score.true_false", MagicMock(name="pyrit.score.true_false")),
    (
        "pyrit.score.true_false.self_ask_true_false_scorer",
        MagicMock(name="pyrit.score.true_false.self_ask_true_false_scorer"),
    ),
    ("pyrit.models.attack_result", MagicMock(name="pyrit.models.attack_result")),
    ("tqdm", MagicMock(name="tqdm")),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.pyrit.scanner_target import ScannerTarget  # noqa: E402
from pentester.scanners.models.target_response import TargetResponse  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_piece(
    text: str = "hello",
    conversation_id: str = "cid-1",
    role: str = "user",
) -> MagicMock:
    piece = MagicMock()
    piece.converted_value = text
    piece.conversation_id = conversation_id
    piece.role = role
    return piece


def _make_message(text: str = "hello", conversation_id: str = "cid-1") -> MagicMock:
    message = MagicMock()
    message.message_pieces = [_make_piece(text, conversation_id)]
    return message


def _make_scanner(
    response: str = "{}",
    bypassed: bool = True,
    score: float = 0.9,
) -> MagicMock:
    scanner = MagicMock()
    scanner.request_handler.__class__.__name__ = "CurlHandler"
    scanner.scan.return_value = TargetResponse(
        response=response, bypassed=bypassed, score=score, text=response
    )
    return scanner


def _make_response_piece(text: str = "response") -> MagicMock:
    piece = MagicMock()
    piece.converted_value = text
    return piece


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# send_prompt_async
# ---------------------------------------------------------------------------


class TestSendPromptAsync:
    def test_serializes_single_turn_as_role_prefixed_text(self) -> None:
        scanner = _make_scanner()
        target = ScannerTarget(scanner)
        _run(target.send_prompt_async(message=_make_message("my prompt")))
        scanner.scan.assert_called_once_with("user: my prompt")

    def test_includes_prior_turns_in_serialized_text(self) -> None:
        prior_piece = _make_piece("first message", role="user")
        prior_msg = MagicMock()
        prior_msg.message_pieces = [prior_piece]

        scanner = _make_scanner()
        target = ScannerTarget(scanner)
        target._memory.get_conversation.return_value = [prior_msg]
        _run(target.send_prompt_async(message=_make_message("second message")))
        sent = scanner.scan.call_args.args[0]
        assert "user: first message" in sent
        assert "user: second message" in sent

    def test_returns_list_of_one_message(self) -> None:
        target = ScannerTarget(_make_scanner())
        result = _run(target.send_prompt_async(message=_make_message()))
        assert len(result) == 1

    def test_response_contains_scanner_response_text(self) -> None:
        scanner = _make_scanner(response="{}")
        target = ScannerTarget(scanner)
        _pyrit_models_mod.MessagePiece.return_value.to_message.return_value = (
            MagicMock()
        )
        _run(target.send_prompt_async(message=_make_message()))
        _, kwargs = _pyrit_models_mod.MessagePiece.call_args
        assert kwargs["original_value"] == "{}"
        assert kwargs["converted_value"] == "{}"

    def test_response_piece_role_is_assistant(self) -> None:
        target = ScannerTarget(_make_scanner())
        _run(target.send_prompt_async(message=_make_message()))
        _, kwargs = _pyrit_models_mod.MessagePiece.call_args
        assert kwargs["role"] == "assistant"

    def test_response_piece_has_bypassed_metadata(self) -> None:
        scanner = _make_scanner(bypassed=True)
        target = ScannerTarget(scanner)
        _run(target.send_prompt_async(message=_make_message()))
        _, kwargs = _pyrit_models_mod.MessagePiece.call_args
        assert kwargs["prompt_metadata"]["bypassed"] == "True"

    def test_response_piece_conversation_id_matches_request(self) -> None:
        target = ScannerTarget(_make_scanner())
        _run(target.send_prompt_async(message=_make_message(conversation_id="abc-99")))
        _, kwargs = _pyrit_models_mod.MessagePiece.call_args
        assert kwargs["conversation_id"] == "abc-99"


# ---------------------------------------------------------------------------
# _validate_request
# ---------------------------------------------------------------------------


class TestValidateRequest:
    def test_raises_when_no_message_pieces(self) -> None:
        message = MagicMock()
        message.message_pieces = []
        with pytest.raises(ValueError, match="no message pieces"):
            ScannerTarget(_make_scanner())._validate_request(message=message)

    def test_raises_when_prompt_is_blank(self) -> None:
        with pytest.raises(ValueError, match="no text content"):
            ScannerTarget(_make_scanner())._validate_request(
                message=_make_message("   ")
            )


# ---------------------------------------------------------------------------
# is_json_response_supported
# ---------------------------------------------------------------------------


def test_json_response_not_supported() -> None:
    assert ScannerTarget(_make_scanner()).is_json_response_supported() is False


def test_raises_when_text_is_none() -> None:
    scanner = MagicMock()
    scanner.request_handler.__class__.__name__ = "CurlHandler"
    scanner.scan.return_value = TargetResponse(response="{}", bypassed=None)
    target = ScannerTarget(scanner)
    with pytest.raises(ValueError, match="TargetResponse.text is None"):
        _run(target.send_prompt_async(message=_make_message()))
