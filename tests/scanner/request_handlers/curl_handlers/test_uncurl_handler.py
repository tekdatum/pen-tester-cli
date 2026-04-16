from unittest.mock import MagicMock, patch

import pytest

from pentester.scanners.exceptions import CurlParseException
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import (
    UncurlHandler,
)

_CURL_HTTPS = (
    "curl https://api.openai.com/v1/chat/completions"
    " -H 'Content-Type: application/json'"
    " --data-raw '{\"model\": \"gpt-4o-mini\","
    ' "messages": [{"role": "user", "content": $PROMPT}]}\''
)
_CURL_INSECURE = _CURL_HTTPS + " -k"
_CURL_INSECURE_LONG = _CURL_HTTPS + " --insecure"


def _make_handler(curl_command: str = _CURL_HTTPS) -> UncurlHandler:
    return UncurlHandler(curl_command=curl_command, response_serializer=None)


class TestVerify:
    def test_verify_true_by_default(self) -> None:
        handler = _make_handler(_CURL_HTTPS)
        parsed = handler._parse_command(_CURL_HTTPS)
        assert parsed.verify is True

    def test_verify_false_with_short_flag(self) -> None:
        handler = _make_handler(_CURL_INSECURE)
        parsed = handler._parse_command(_CURL_INSECURE)
        assert parsed.verify is False

    def test_verify_false_with_long_flag(self) -> None:
        handler = _make_handler(_CURL_INSECURE_LONG)
        parsed = handler._parse_command(_CURL_INSECURE_LONG)
        assert parsed.verify is False


class TestParseError:
    def test_raises_when_uncurl_cannot_parse(self) -> None:
        handler = _make_handler()
        with pytest.raises(CurlParseException):
            handler._parse_command("no valid url here")
