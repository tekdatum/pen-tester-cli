"""Tests for pentester.auditors.garak.scanner_generator.ScannerGenerator.

garak.* modules are stubbed via sys.modules before the module under test is
imported so the suite runs without the real garak package installed.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub garak modules before any local imports
# ---------------------------------------------------------------------------

_garak_config_mod = MagicMock(name="garak._config")
_garak_attempt_mod = MagicMock(name="garak.attempt")
_garak_generators_base_mod = MagicMock(name="garak.generators.base")
_garak_mod = MagicMock(name="garak")


# Generator base class — must be a real class so ScannerGenerator can inherit
class _FakeGenerator:
    def __init__(self, name: str, config_root: object = None) -> None:
        self.name = name


_garak_generators_base_mod.Generator = _FakeGenerator


# Message stub — just holds .text
class _FakeMessage:
    def __init__(self, text: str = "") -> None:
        self.text = text


_garak_attempt_mod.Message = _FakeMessage

for _name, _stub in [
    ("garak", _garak_mod),
    ("garak._config", _garak_config_mod),
    ("garak.attempt", _garak_attempt_mod),
    ("garak.generators", MagicMock(name="garak.generators")),
    ("garak.generators.base", _garak_generators_base_mod),
]:
    sys.modules.setdefault(_name, _stub)

# Re-read after potential earlier registration
_garak_attempt_mod = sys.modules["garak.attempt"]
_garak_generators_base_mod = sys.modules["garak.generators.base"]

from pentester.auditors.garak.scanner_generator import ScannerGenerator  # noqa: E402
from pentester.scanners.models.target_response import TargetResponse  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scanner(text: str = "hello world") -> MagicMock:
    scanner = MagicMock()
    scanner.scan.return_value = TargetResponse(response="raw", bypassed=None, text=text)
    return scanner


def _make_prompt(text: str = "attack prompt") -> MagicMock:
    turn = MagicMock()
    turn.content.text = text
    prompt = MagicMock()
    prompt.turns = [turn]
    return prompt


# ---------------------------------------------------------------------------
# _call_model
# ---------------------------------------------------------------------------


class TestCallModel:
    def test_calls_scanner_scan_with_last_turn_text(self) -> None:
        scanner = _make_scanner()
        gen = ScannerGenerator(scanner)
        gen._call_model(_make_prompt("inject this"))
        scanner.scan.assert_called_once_with("inject this")

    def test_returns_list_with_one_message(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        result = gen._call_model(_make_prompt())
        assert len(result) == 1

    def test_returned_message_contains_response_text(self) -> None:
        gen = ScannerGenerator(_make_scanner(text="hello world"))
        result = gen._call_model(_make_prompt())
        assert result[0].text == "hello world"

    def test_raises_when_text_is_none(self) -> None:
        scanner = MagicMock()
        scanner.scan.return_value = TargetResponse(response="{}", bypassed=None)
        gen = ScannerGenerator(scanner)
        with pytest.raises(ValueError, match="TargetResponse.text is None"):
            gen._call_model(_make_prompt())
