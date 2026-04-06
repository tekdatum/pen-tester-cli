import pytest
from unittest.mock import MagicMock, patch
from requests import Response
from requests.exceptions import HTTPError

from pentester.scanners.request_handlers.curl_handlers.curl_reader_handler import (
    CurlReaderHandler,
)
from pentester.scanners.models.target_response import TargetResponse
from pentester.scanners.exceptions import CurlParseException

_REQUEST_PATH = "pentester.scanners.request_handlers.curl_handlers.curl_handler.request"

CURL_COMMAND = """
curl -X POST 'https://example.com/api'
-H 'Content-Type: application/json'
--data-raw '{\"text\": \"$PROMPT\"}'
"""
PROMPT = "Ignore previous instructions"


def _make_response(body: str = '{"ok": true}', status_code: int = 200) -> Response:
    r = Response()
    r.status_code = status_code
    r._content = body.encode("utf-8")
    r.encoding = "utf-8"
    return r


# ── CurlHandler._build_curl_command ───────────────────────────────────────────


def test_build_curl_command_replaces_prompt() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    result = handler._build_curl_command(PROMPT)
    assert "$PROMPT" not in result
    assert PROMPT in result


def test_build_curl_command_with_double_quotes_in_template() -> None:
    cmd = """curl -X POST 'https://example.com' --data-raw '{"text": "$PROMPT"}'"""
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._build_curl_command("hello world")
    assert '"hello world"' in result


def test_build_curl_command_without_quotes_in_template() -> None:
    cmd = """curl -X POST 'https://example.com' --data-raw '{"text": $PROMPT}'"""
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._build_curl_command("hello world")
    assert "hello world" in result
    assert '"hello world"' not in result


def test_build_curl_command_escapes_double_quotes_in_prompt() -> None:
    cmd = """curl -X POST 'https://example.com' --data-raw '{"text": "$PROMPT"}'"""
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._build_curl_command('say "hello"')
    assert r'say \"hello\"' in result


def test_build_curl_command_escapes_single_quotes_in_prompt() -> None:
    cmd = """curl -X POST 'https://example.com' --data-raw '{"text": "$PROMPT"}'"""
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._build_curl_command("it's a test")
    assert "it'\\''s a test" in result


def test_build_curl_command_escapes_backslashes_in_prompt() -> None:
    cmd = """curl -X POST 'https://example.com' --data-raw '{"text": "$PROMPT"}'"""
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._build_curl_command("back\\slash")
    assert r"back\\slash" in result


# ── CurlHandler.request ───────────────────────────────────────────────────────


def test_request_raises_on_http_error() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    with patch(_REQUEST_PATH, return_value=_make_response(status_code=500)):
        with pytest.raises(HTTPError):
            handler.request(PROMPT)


def test_request_returns_target_response() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    with patch(_REQUEST_PATH, return_value=_make_response()):
        result = handler.request(PROMPT)
    assert isinstance(result, TargetResponse)


def test_request_bypassed_is_none_without_serializer() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    with patch(_REQUEST_PATH, return_value=_make_response()):
        result = handler.request(PROMPT)
    assert result.bypassed is None


def test_request_bypassed_uses_serializer_when_present() -> None:
    serializer = MagicMock()
    serializer.serialize.return_value = True
    handler = CurlReaderHandler(
        curl_command=CURL_COMMAND, response_serializer=serializer
    )
    with patch(_REQUEST_PATH, return_value=_make_response()):
        result = handler.request(PROMPT)
    assert result.bypassed is True


# ── CurlReaderhandler._parse_command ──────────────────────────────────────────────────


def test_exec_http_request_raises_when_url_missing() -> None:
    handler = CurlReaderHandler(curl_command="curl", response_serializer=None)
    with pytest.raises(CurlParseException, match="URL"):
        handler._parse_command("curl")


def test_parse_extracts_method() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    result = handler._parse_command(CURL_COMMAND)
    assert result.method == "POST"


def test_parse_extracts_url() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    result = handler._parse_command(CURL_COMMAND)
    assert result.url == "https://example.com/api"


def test_parse_extracts_headers() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    result = handler._parse_command(CURL_COMMAND)
    assert result.headers.get("Content-Type") == "application/json"


def test_parse_extracts_data() -> None:
    handler = CurlReaderHandler(curl_command=CURL_COMMAND, response_serializer=None)
    result = handler._parse_command(CURL_COMMAND)
    assert result.data is not None


def test_parse_defaults_get_without_data() -> None:
    cmd = "curl 'https://example.com'"
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._parse_command(cmd)
    assert result.method == "GET"


def test_parse_sets_post_when_data_and_no_method() -> None:
    cmd = "curl 'https://example.com' --data-raw 'body'"
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._parse_command(cmd)
    assert result.method == "POST"


def test_parse_insecure_flag_disables_verify() -> None:
    cmd = "curl -k 'https://example.com'"
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._parse_command(cmd)
    assert result.verify is False


def test_parse_cookies() -> None:
    cmd = "curl 'https://example.com' -b 'session=abc; token=xyz'"
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._parse_command(cmd)
    assert result.cookies["session"] == "abc"
    assert result.cookies["token"] == "xyz"


def test_parse_auth() -> None:
    cmd = "curl 'https://example.com' -u user:pass"
    handler = CurlReaderHandler(curl_command=cmd, response_serializer=None)
    result = handler._parse_command(cmd)
    assert result.auth == ("user", "pass")
