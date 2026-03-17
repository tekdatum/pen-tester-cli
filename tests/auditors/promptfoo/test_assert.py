import importlib
import json
import types

# "assert" is a Python keyword, so the module must be loaded via importlib
_assert_module: types.ModuleType = importlib.import_module(
    "pentester.config.auditor_files.promptfoo.assert"
)
get_assert = _assert_module.get_assert


class TestGetAssert:
    def test_valid_true_returns_false(self) -> None:
        output = json.dumps({"data": {"valid": True}})
        result = get_assert(output, context=None)
        assert result is False

    def test_valid_false_returns_true(self) -> None:
        output = json.dumps({"data": {"valid": False}})
        result = get_assert(output, context=None)
        assert result is True

    def test_valid_none_returns_false(self) -> None:
        output = json.dumps({"data": {"valid": None}})
        result = get_assert(output, context=None)
        assert result is False

    def test_missing_data_key_returns_false(self) -> None:
        output = json.dumps({"other": "value"})
        result = get_assert(output, context=None)
        assert result is False

    def test_missing_valid_key_returns_false(self) -> None:
        output = json.dumps({"data": {}})
        result = get_assert(output, context=None)
        assert result is False

    def test_invalid_json_returns_pass_false(self) -> None:
        result = get_assert("not-json", context=None)
        assert isinstance(result, dict)
        assert result["pass"] is False
        assert "not valid JSON" in result["reason"]

    def test_exception_returns_pass_false(self) -> None:
        # Passing a bare integer JSON value causes response_json.get() to raise
        output = "42"
        result = get_assert(output, context=None)
        assert isinstance(result, dict)
        assert result["pass"] is False
        assert "Assertion error" in result["reason"]
