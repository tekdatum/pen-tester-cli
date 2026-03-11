import pytest
from pentester.scanners.exceptions import CustomHandlerLoadException
from pentester.scanners.scanner import Scanner, _load_handler_from_file
from pentester.scanners.models.handler_response import HandlerResponse
from pentester.scanners.request_handlers.custom_handler.custom_handler import (
    CustomHandler,
)
from pentester.config.scanner import ScannerSettings

VALID_HANDLER_SRC = """
from pentester.scanners.models.handler_response import HandlerResponse
from pentester.scanners.request_handlers.custom_handler.custom_handler import CustomHandler

class MyHandler(CustomHandler):
    def request(self, text: str) -> HandlerResponse:
        return HandlerResponse(response="blocked", passed=False)
"""

NOT_A_SUBCLASS_SRC = """
class NotAHandler:
    def request(self, text): ...
"""


def _write(tmp_path, name: str, src: str) -> str:
    f = tmp_path / name
    f.write_text(src)
    return str(f)


# ── format validation ─────────────────────────────────────────────────────────


def test_load_raises_on_missing_colon() -> None:
    with pytest.raises(CustomHandlerLoadException, match="Expected format"):
        _load_handler_from_file("my_handler.py")


# ── file errors ───────────────────────────────────────────────────────────────


def test_load_raises_on_file_not_found() -> None:
    with pytest.raises(CustomHandlerLoadException, match="File not found"):
        _load_handler_from_file("/nonexistent/handler.py:MyHandler")


# ── class errors ─────────────────────────────────────────────────────────────


def test_load_raises_on_class_not_found(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", VALID_HANDLER_SRC)
    with pytest.raises(CustomHandlerLoadException, match="not found"):
        _load_handler_from_file(f"{path}:WrongClass")


def test_load_raises_when_class_not_subclass(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", NOT_A_SUBCLASS_SRC)
    with pytest.raises(CustomHandlerLoadException, match="subclass"):
        _load_handler_from_file(f"{path}:NotAHandler")


# ── success ───────────────────────────────────────────────────────────────────


def test_load_returns_custom_handler_instance(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", VALID_HANDLER_SRC)
    handler = _load_handler_from_file(f"{path}:MyHandler")
    assert isinstance(handler, CustomHandler)


def test_loaded_handler_request_returns_handler_response(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", VALID_HANDLER_SRC)
    handler = _load_handler_from_file(f"{path}:MyHandler")
    result = handler.request("test prompt")
    assert isinstance(result, HandlerResponse)


# ── Scanner.from_settings ─────────────────────────────────────────────────────


def test_from_settings_with_custom_handler_returns_scanner(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", VALID_HANDLER_SRC)
    settings = ScannerSettings(custom_handler=f"{path}:MyHandler")
    assert isinstance(Scanner.from_settings(settings), Scanner)


def test_from_settings_custom_handler_takes_priority_over_curl(tmp_path) -> None:
    path = _write(tmp_path, "handler.py", VALID_HANDLER_SRC)
    settings = ScannerSettings(
        custom_handler=f"{path}:MyHandler",
        curl_command="curl https://example.com",
    )
    scanner = Scanner.from_settings(settings)
    assert scanner is not None
    result = scanner.scan("prompt")
    assert result.response == "blocked"
