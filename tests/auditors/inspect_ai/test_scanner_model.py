"""Tests for pentester.auditors.inspect_ai.scanner_model.ScannerModelAPI."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from pentester.auditors.inspect_ai.scanner_model import ScannerModelAPI  # noqa: E402
from pentester.scanners.models.target_response import TargetResponse  # noqa: E402


# ---------------------------------------------------------------------------
# TestScannerModelAPI
# ---------------------------------------------------------------------------


class TestScannerModelAPI:
    """Tests for the ScannerModelAPI custom inspect_ai model provider."""

    def _make_api(self, scanner: MagicMock | None = None) -> ScannerModelAPI:
        return ScannerModelAPI(
            model_name="scanner/default",
            scanner=scanner or MagicMock(),
        )

    def _make_message(self, content: str, role: str = "user") -> MagicMock:
        msg = MagicMock()
        msg.text = content
        msg.content = content
        msg.role = role
        return msg

    def test_model_name_stored_on_instance(self) -> None:
        api = self._make_api()
        assert api.model_name == "scanner/default"

    def test_scanner_stored_on_instance(self) -> None:
        mock_scanner = MagicMock()
        api = ScannerModelAPI(model_name="scanner/default", scanner=mock_scanner)
        assert api._scanner is mock_scanner

    def test_generate_calls_scanner_scan_with_extracted_prompt(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = TargetResponse(
            response="safe reply", bypassed=False
        )
        api = self._make_api(scanner=mock_scanner)
        msg = self._make_message("attack prompt")
        with patch(
            "pentester.auditors.inspect_ai.scanner_model.ModelOutput"
        ) as _m_output:
            asyncio.run(api.generate([msg], [], None, MagicMock()))
        expected = json.dumps([{"role": "user", "content": "attack prompt"}], ensure_ascii=False)
        mock_scanner.scan.assert_called_once_with(expected)

    def test_generate_returns_model_output_with_response_text(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = TargetResponse(
            response="blocked", bypassed=False
        )
        api = self._make_api(scanner=mock_scanner)
        msg = self._make_message("evil prompt")
        with patch(
            "pentester.auditors.inspect_ai.scanner_model.ModelOutput"
        ) as m_output_cls:
            asyncio.run(api.generate([msg], [], None, MagicMock()))
        assert m_output_cls.called
        assert m_output_cls.call_args.kwargs.get("model") == "scanner/default"

    def test_generate_uses_last_message_as_prompt(self) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = TargetResponse(response="ok", bypassed=False)
        api = self._make_api(scanner=mock_scanner)
        msg1 = self._make_message("system message")
        msg2 = self._make_message("user attack")
        with patch("pentester.auditors.inspect_ai.scanner_model.ModelOutput"):
            asyncio.run(api.generate([msg1, msg2], [], None, MagicMock()))
        expected = json.dumps(
            [
                {"role": "user", "content": "system message"},
                {"role": "user", "content": "user attack"},
            ],
            ensure_ascii=False,
        )
        mock_scanner.scan.assert_called_once_with(expected)

    def test_extract_prompt_from_messages_uses_text_property(self) -> None:
        api = self._make_api()
        msg = MagicMock()
        msg.role = "user"
        msg.text = "text from property"
        msg.content = "content field"
        result = api._extract_prompt_from_messages([msg])
        expected = json.dumps([{"role": "user", "content": "text from property"}], ensure_ascii=False)
        assert result == expected

    def test_extract_prompt_from_messages_falls_back_to_content(self) -> None:
        api = self._make_api()
        msg = MagicMock()
        msg.role = "user"
        msg.text = ""
        msg.content = "content only"
        result = api._extract_prompt_from_messages([msg])
        expected = json.dumps([{"role": "user", "content": "content only"}], ensure_ascii=False)
        assert result == expected

    def test_extract_prompt_from_messages_empty_list_returns_empty(self) -> None:
        api = self._make_api()
        assert api._extract_prompt_from_messages([]) == "[]"
