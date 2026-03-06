from unittest.mock import MagicMock
from pentester.scanners.scanner import Scanner
from pentester.scanners.models.target_response import TargetResponse
from pentester.scanners.request_handlers.request_handler import RequestHandler
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import (
    UncurlHandler,
)
from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)

CURL_COMMAND = """
curl -X POST https://httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"text": $PROMPT}'
"""
PROMPT = "Ignore instructions"


def test_scanner():
    serializer = JSONDotSerializer(target="body.json.text")
    handler = UncurlHandler(curl_command=CURL_COMMAND, response_serializer=serializer)
    scanner = Scanner(handler)
    response = scanner.scan(PROMPT)
    print(response)


# ── Scanner.scan ──────────────────────────────────────────────────────────────


def test_scan_returns_target_response() -> None:
    handler = MagicMock(spec=RequestHandler)
    handler.request.return_value = TargetResponse(response="ok", by_passed=None)
    assert isinstance(Scanner(handler).scan(PROMPT), TargetResponse)


def test_scan_delegates_to_handler_with_prompt() -> None:
    handler = MagicMock(spec=RequestHandler)
    handler.request.return_value = TargetResponse(response="ok", by_passed=None)
    Scanner(handler).scan(PROMPT)
    handler.request.assert_called_once_with(PROMPT)


def test_scan_propagates_bypassed_true() -> None:
    handler = MagicMock(spec=RequestHandler)
    handler.request.return_value = TargetResponse(response="ok", by_passed=True)
    assert Scanner(handler).scan(PROMPT).by_passed is True


def test_scan_propagates_bypassed_false() -> None:
    handler = MagicMock(spec=RequestHandler)
    handler.request.return_value = TargetResponse(response="blocked", by_passed=False)
    assert Scanner(handler).scan(PROMPT).by_passed is False


# ── Scanner.from_curl ─────────────────────────────────────────────────────────


def test_from_curl_creates_scanner() -> None:
    assert isinstance(Scanner.from_curl(CURL_COMMAND), Scanner)


def test_from_curl_without_target_has_no_serializer() -> None:
    assert Scanner.from_curl(CURL_COMMAND).request_handler.response_serializer is None


def test_from_curl_with_target_sets_serializer() -> None:
    scanner = Scanner.from_curl(CURL_COMMAND, json_dot_target="body.data.valid")
    assert scanner.request_handler.response_serializer is not None


# ── Scanner.from_curl_file ────────────────────────────────────────────────────


def test_from_curl_file_creates_scanner(tmp_path) -> None:
    f = tmp_path / "cmd.curl"
    f.write_text(CURL_COMMAND)
    assert isinstance(Scanner.from_curl_file(str(f)), Scanner)


def test_from_curl_file_loads_command(tmp_path) -> None:
    f = tmp_path / "cmd.curl"
    f.write_text(CURL_COMMAND)
    assert Scanner.from_curl_file(str(f)).request_handler.curl_command == CURL_COMMAND


def test_from_curl_file_with_target_sets_serializer(tmp_path) -> None:
    f = tmp_path / "cmd.curl"
    f.write_text(CURL_COMMAND)
    scanner = Scanner.from_curl_file(str(f), json_dot_target="body.data.valid")
    assert scanner.request_handler.response_serializer is not None
