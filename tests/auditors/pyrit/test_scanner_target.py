"""Tests for pentester.auditors.pyrit.scanner_target.ScannerTarget."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Stub pyrit modules before importing the module under test.
# ---------------------------------------------------------------------------

def _make_message_piece(role: str, value: str) -> MagicMock:
    piece = MagicMock()
    piece.role = role
    piece.converted_value = value
    return piece


def _make_message(*pieces: MagicMock) -> MagicMock:
    msg = MagicMock()
    msg.message_pieces = list(pieces)
    return msg


class _FakePromptChatTarget:
    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        pass


_pyrit_models_mod = MagicMock(name="pyrit.models")
_pyrit_prompt_target_mod = MagicMock(name="pyrit.prompt_target")
_pyrit_prompt_target_mod.PromptChatTarget = _FakePromptChatTarget

for _name, _stub in [
    ("pyrit", MagicMock(name="pyrit")),
    ("pyrit.models", _pyrit_models_mod),
    ("pyrit.prompt_target", _pyrit_prompt_target_mod),
]:
    sys.modules.setdefault(_name, _stub)

from pentester.auditors.pyrit.scanner_target import ScannerTarget  # noqa: E402


class TestSerializeConversation:
    def _make_target(self) -> ScannerTarget:
        target = object.__new__(ScannerTarget)
        target.scanner = MagicMock()
        return target

    def test_single_message_single_piece(self) -> None:
        target = self._make_target()
        conversation = [_make_message(_make_message_piece("user", "hello"))]
        assert target._serialize_conversation(conversation) == "user: hello"

    def test_multiple_messages(self) -> None:
        target = self._make_target()
        conversation = [
            _make_message(_make_message_piece("user", "hi")),
            _make_message(_make_message_piece("assistant", "hello")),
            _make_message(_make_message_piece("user", "how are you?")),
        ]
        result = target._serialize_conversation(conversation)
        assert result == "user: hi\nassistant: hello\nuser: how are you?"

    def test_message_with_multiple_pieces(self) -> None:
        target = self._make_target()
        conversation = [
            _make_message(
                _make_message_piece("user", "part one"),
                _make_message_piece("user", "part two"),
            )
        ]
        result = target._serialize_conversation(conversation)
        assert result == "user: part one\nuser: part two"
