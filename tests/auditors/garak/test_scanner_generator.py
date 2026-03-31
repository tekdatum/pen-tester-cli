"""Tests for pentester.auditors.garak.scanner_generator.ScannerGenerator.

garak.* modules are stubbed via sys.modules before the module under test is
imported so the suite runs without the real garak package installed.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

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

from pentester.auditors.garak.scanner_generator import (  # noqa: E402
    ScannerGenerator,
    _DEFAULT_RESPONSE_PATH,
)
from pentester.scanners.models.target_response import TargetResponse  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OPENAI_BODY = json.dumps(
    {"choices": [{"message": {"role": "assistant", "content": "hello world"}}]}
)
_ANTHROPIC_BODY = json.dumps({"content": [{"type": "text", "text": "hello world"}]})
_HTTP_PREFIX = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"


def _make_raw_http(body: str) -> str:
    return f"{_HTTP_PREFIX}{body}"


def _make_scanner(raw_http: str = _make_raw_http(_OPENAI_BODY)) -> MagicMock:
    scanner = MagicMock()
    scanner.scan.return_value = TargetResponse(response=raw_http, bypassed=None)
    return scanner


def _make_prompt(text: str = "attack prompt") -> MagicMock:
    turn = MagicMock()
    turn.content.text = text
    prompt = MagicMock()
    prompt.turns = [turn]
    return prompt


# ---------------------------------------------------------------------------
# _extract_llm_text — default OpenAI path
# ---------------------------------------------------------------------------


class TestExtractLlmTextDefault:
    def test_extracts_content_from_openai_format(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        result = gen._extract_llm_text(_make_raw_http(_OPENAI_BODY))
        assert result == "hello world"

    def test_splits_on_blank_line_to_find_body(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        result = gen._extract_llm_text(_make_raw_http(_OPENAI_BODY))
        assert result == "hello world"

    def test_handles_response_without_http_prefix(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        result = gen._extract_llm_text(_OPENAI_BODY)
        assert result == "hello world"

    def test_default_path_constant_is_openai_format(self) -> None:
        assert _DEFAULT_RESPONSE_PATH == "choices.0.message.content"


# ---------------------------------------------------------------------------
# _extract_llm_text — custom response_text_target
# ---------------------------------------------------------------------------


class TestExtractLlmTextCustomPath:
    def test_custom_path_extracts_anthropic_format(self) -> None:
        gen = ScannerGenerator(
            _make_scanner(), response_text_target="content.0.text"
        )
        result = gen._extract_llm_text(_make_raw_http(_ANTHROPIC_BODY))
        assert result == "hello world"

    def test_numeric_key_indexes_into_list(self) -> None:
        body = json.dumps({"items": ["zero", "one", "two"]})
        gen = ScannerGenerator(_make_scanner(), response_text_target="items.1")
        assert gen._extract_llm_text(body) == "one"

    def test_nested_path_traversal(self) -> None:
        body = json.dumps({"a": {"b": {"c": "deep value"}}})
        gen = ScannerGenerator(_make_scanner(), response_text_target="a.b.c")
        assert gen._extract_llm_text(body) == "deep value"


# ---------------------------------------------------------------------------
# _extract_llm_text — misconfiguration: warn + raise
# ---------------------------------------------------------------------------


class TestExtractLlmTextMisconfigured:
    def test_raises_on_invalid_json(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        with pytest.raises(Exception):
            gen._extract_llm_text("HTTP/1.1 200 OK\n\nnot-json")

    def test_warns_on_invalid_json(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        with patch("pentester.auditors.garak.scanner_generator.logger") as mock_log:
            with pytest.raises(Exception):
                gen._extract_llm_text("HTTP/1.1 200 OK\n\nnot-json")
        mock_log.warning.assert_called_once()

    def test_raises_on_missing_path_key(self) -> None:
        body = json.dumps({"other": "field"})
        gen = ScannerGenerator(_make_scanner())  # default path won't match
        with pytest.raises(Exception):
            gen._extract_llm_text(body)

    def test_warns_on_missing_path_key(self) -> None:
        body = json.dumps({"other": "field"})
        gen = ScannerGenerator(_make_scanner())
        with patch("pentester.auditors.garak.scanner_generator.logger") as mock_log:
            with pytest.raises(Exception):
                gen._extract_llm_text(body)
        mock_log.warning.assert_called_once()

    def test_raises_on_index_out_of_range(self) -> None:
        body = json.dumps({"choices": []})
        gen = ScannerGenerator(_make_scanner())
        with pytest.raises(Exception):
            gen._extract_llm_text(body)

    def test_warning_includes_path_name(self) -> None:
        body = json.dumps({"other": "field"})
        gen = ScannerGenerator(_make_scanner(), response_text_target="my.custom.path")
        with patch("pentester.auditors.garak.scanner_generator.logger") as mock_log:
            with pytest.raises(Exception):
                gen._extract_llm_text(body)
        warning_msg = str(mock_log.warning.call_args)
        assert "my.custom.path" in warning_msg


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

    def test_returned_message_contains_extracted_text(self) -> None:
        gen = ScannerGenerator(_make_scanner())
        result = gen._call_model(_make_prompt())
        assert result[0].text == "hello world"

    def test_extraction_error_propagates_from_call_model(self) -> None:
        scanner = MagicMock()
        scanner.scan.return_value = TargetResponse(
            response="HTTP/1.1 200 OK\n\nnot-json", bypassed=None
        )
        gen = ScannerGenerator(scanner)
        with pytest.raises(Exception):
            gen._call_model(_make_prompt())
