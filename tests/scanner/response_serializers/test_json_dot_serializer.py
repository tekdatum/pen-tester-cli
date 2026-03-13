import pytest
from requests import Response

from pentester.scanners.exceptions import SerializeException
from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)


def _make_response(body: str, status_code: int = 200) -> Response:
    r = Response()
    r.status_code = status_code
    r._content = body.encode("utf-8")
    r.encoding = "utf-8"
    return r


# ── body ──────────────────────────────────────────────────────────────────────


def test_serialize_body_top_level_key() -> None:
    response = _make_response('{"valid": true}')
    result = JSONDotSerializer("body.valid").serialize(response)
    assert result is True


def test_serialize_body_nested_key() -> None:
    response = _make_response('{"data": {"valid": false}}')
    result = JSONDotSerializer("body.data.valid").serialize(response)
    assert result is False


def test_serialize_body_array_index() -> None:
    response = _make_response('{"choices": [{"text": "hello"}]}')
    result = JSONDotSerializer("body.choices.0.text").serialize(response)
    assert result == "hello"


def test_serialize_body_returns_string() -> None:
    response = _make_response('{"message": "ok"}')
    result = JSONDotSerializer("body.message").serialize(response)
    assert result == "ok"


def test_serialize_body_returns_number() -> None:
    response = _make_response('{"score": 42}')
    result = JSONDotSerializer("body.score").serialize(response)
    assert result == 42


# ── headers ───────────────────────────────────────────────────────────────────


def test_serialize_header() -> None:
    response = _make_response("{}")
    response.headers["X-Custom"] = "value123"
    result = JSONDotSerializer("headers.X-Custom").serialize(response)
    assert result == "value123"


# ── errores ───────────────────────────────────────────────────────────────────


def test_serialize_unknown_section_raises() -> None:
    response = _make_response("{}")
    with pytest.raises(ValueError, match="Unknown section"):
        JSONDotSerializer("meta.something").serialize(response)


def test_serialize_missing_key_raises() -> None:
    response = _make_response('{"data": {}}')
    with pytest.raises(SerializeException):
        JSONDotSerializer("body.data.missing").serialize(response)


def test_serialize_invalid_json_raises() -> None:
    response = _make_response("not json")
    with pytest.raises(SerializeException):
        JSONDotSerializer("body.key").serialize(response)


def test_serialize_missing_header_raises() -> None:
    response = _make_response("{}")
    with pytest.raises(SerializeException):
        JSONDotSerializer("headers.X-Missing").serialize(response)
