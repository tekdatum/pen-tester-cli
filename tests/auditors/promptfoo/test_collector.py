import json
from pathlib import Path

import pandas as pd
import pytest

from pentester.auditors.promptfoo.collector import PromptfooResultCollector


def _make_collector(results_path: Path) -> PromptfooResultCollector:
    return PromptfooResultCollector(results_path=results_path)


def _make_jsonl_row(
    provider_id: str = "http://example.com",
    prompt_raw: str = "test prompt",
    vars_input: str = "input text",
    valid: bool = True,
    reason_code: str = "injection",
    duration: float = 1.5,
    accept_score: float = 0.9,
    reject_score: float = 0.1,
    latency_ms: int = 200,
    http_status: int = 200,
    cached: bool = False,
    raw_response: object = None,
    strategy_id: str = "base64",
    plugin_id: str = "competitors",
    error: str | None = None,
    success: bool = True,
    score: float = 1.0,
    failure_reason: int | str = 0,
    grading_reason: str = "All assertions passed",
) -> dict:
    row: dict = {
        "provider": {"id": provider_id},
        "prompt": {"raw": prompt_raw},
        "vars": {"input": vars_input},
        "response": {
            "raw": raw_response or {
                "data": {
                    "valid": valid,
                    "reason_code": reason_code,
                    "duration": duration,
                    "extra": {"accept_score": accept_score, "reject_score": reject_score}
                }
            },
            "latencyMs": latency_ms,
            "cached": cached,
            "metadata": {"http": {"status": http_status}},
        },
        "metadata": {"strategyId": strategy_id, "pluginId": plugin_id},
        "success": success,
        "score": score,
        "failureReason": failure_reason,
        "gradingResult": {"reason": grading_reason},
    }
    if error is not None:
        row["error"] = error
    return row


class TestClean:
    def test_deletes_jsonl_files_and_returns_count(self, tmp_path: Path) -> None:
        (tmp_path / "file1.jsonl").write_text("data")
        (tmp_path / "file2.jsonl").write_text("data")
        (tmp_path / "keep.txt").write_text("keep")
        
        collector = _make_collector(tmp_path)
        count = collector.clean()
        
        assert count == 2
        assert list(tmp_path.glob("*.jsonl")) == []
        assert (tmp_path / "keep.txt").exists()

    def test_returns_zero_when_no_jsonl_files_exist(self, tmp_path: Path) -> None:
        assert _make_collector(tmp_path).clean() == 0


class TestValidate:
    def test_returns_true_for_valid_row_counts(self, tmp_path: Path) -> None:
        collector = _make_collector(tmp_path)
        jsonl = tmp_path / "result.jsonl"
        
        # Exact match
        jsonl.write_text("line1\nline2\nline3\n")
        assert collector.validate(Path("test.yaml"), jsonl, 3) is True
        
        # Ignores blank lines
        jsonl.write_text("line1\n\nline2\n\n")
        assert collector.validate(Path("test.yaml"), jsonl, 2) is True
        
        # Zero expected and empty file
        jsonl.write_text("")
        assert collector.validate(Path("test.yaml"), jsonl, 0) is True

    def test_returns_false_for_invalid_conditions(self, tmp_path: Path) -> None:
        collector = _make_collector(tmp_path)
        jsonl = tmp_path / "result.jsonl"
        jsonl.write_text("line1\nline2\n")
        
        # Missing file
        assert collector.validate(Path("test.yaml"), tmp_path / "missing.jsonl", 5) is False
        
        # Count mismatch (under)
        assert collector.validate(Path("test.yaml"), jsonl, 5) is False
        
        # Count mismatch (over)
        assert collector.validate(Path("test.yaml"), jsonl, 1) is False


class TestParseRawResponse:
    def test_extracts_and_parses_valid_raw_data(self) -> None:
        # Handles raw dicts and nested dicts
        assert PromptfooResultCollector._parse_raw_response({"raw": {"key": "value"}}) == {"key": "value"}
        assert PromptfooResultCollector._parse_raw_response({"raw": {"data": {"nested": True}}}) == {"data": {"nested": True}}
        
        # Handles valid json strings
        assert PromptfooResultCollector._parse_raw_response({"raw": '{"key": "string_value"}'}) == {"key": "string_value"}

    def test_handles_invalid_or_missing_raw_data(self) -> None:
        assert PromptfooResultCollector._parse_raw_response({"raw": "not json"}) == {}
        assert PromptfooResultCollector._parse_raw_response("not a dict") == {}
        assert PromptfooResultCollector._parse_raw_response({"other": "data"}) == {}
        assert PromptfooResultCollector._parse_raw_response(None) == {}
        assert PromptfooResultCollector._parse_raw_response({"raw": None}) is None


class TestReadJsonlFile:
    def test_returns_dataframe_for_valid_jsonl(self, tmp_path: Path) -> None:
        jsonl = tmp_path / "valid.jsonl"
        lines = [json.dumps({"x": i}) for i in range(5)]
        jsonl.write_text("\n".join(lines) + "\n")
        
        result = _make_collector(tmp_path)._read_jsonl_file(jsonl)
        
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 5

    def test_returns_none_for_invalid_or_empty_files(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.jsonl"
        bad_file = tmp_path / "bad.jsonl"
        empty_file.write_text("")
        bad_file.write_text("not valid json at all {{{")
        
        collector = _make_collector(tmp_path)
        assert collector._read_jsonl_file(empty_file) is None
        assert collector._read_jsonl_file(bad_file) is None


class TestExtractRows:
    def test_maps_all_columns_correctly_from_valid_row(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        
        raw_response = {
            "data": {
                "valid": True, 
                "reason_code": "xss", 
                "duration": 3.14, 
                "extra": {"accept_score": 0.85, "reject_score": 0.15}
            }
        }
        
        df = pd.DataFrame([_make_jsonl_row(
            provider_id="http://my-api.com",
            prompt_raw="my prompt",
            vars_input="user input",
            latency_ms=500,
            http_status=201,
            cached=True,
            raw_response=raw_response,
            strategy_id="jailbreak-templates",
            plugin_id="competitors",
        )])

        result = collector._extract_rows(df, "test.jsonl")

        # Verify schema structure
        expected_cols = {
            "provider_url", "prompt", "input", "valid", "reason_code",
            "duration", "accept_score", "reject_score", "latency_ms",
            "http_status", "cached", "api_response", "source_file",
            "strategy_id", "plugin_id", "error",
            "success", "grading_score", "grading_reason", "conversation",
            "multiturn_messages", "successful_attacks", "stored_grader_result",
        }
        assert set(result.columns) == expected_cols

        # Verify row mapping accuracy
        row = result.iloc[0]
        assert row["provider_url"] == "http://my-api.com"
        assert row["prompt"] == "my prompt"
        assert row["input"] == "user input"
        assert row["valid"] == True
        assert row["reason_code"] == "xss"
        assert row["duration"] == 3.14
        assert row["accept_score"] == 0.85
        assert row["reject_score"] == 0.15
        assert row["latency_ms"] == 500
        assert row["http_status"] == 201
        assert row["cached"] == True
        assert isinstance(row["api_response"], dict)
        assert row["source_file"] == "test.jsonl"
        assert row["strategy_id"] == "jailbreak-templates"
        assert row["plugin_id"] == "competitors"
        assert row["success"] == True
        assert row["grading_score"] == 1.0
        assert row["grading_reason"] == "All assertions passed"

    def test_handles_missing_nested_keys_gracefully(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([{"provider": {}, "prompt": {}, "vars": {}, "response": {}}])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["provider_url"].iloc[0] is None
        assert result["prompt"].iloc[0] is None
        assert result["strategy_id"].iloc[0] is None
        assert result["plugin_id"].iloc[0] is None
        assert result["success"].iloc[0] is None
        assert result["grading_score"].iloc[0] is None
        assert result["grading_reason"].iloc[0] is None

    def test_includes_error_column_when_error_present(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row(
            error="FileNotFoundError: assert.py not found",
            failure_reason="GRADER_ERROR",
        )])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["error"].iloc[0] == "FileNotFoundError: assert.py not found"

    def test_error_column_is_none_when_no_error(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row()])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["error"].iloc[0] is None

    def test_handles_missing_response_column_gracefully(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        # Rows as produced by promptfoo when the grader fails — no "response" key
        df = pd.DataFrame([
            {
                "provider": {"id": "http://example.com"},
                "prompt": {"raw": "test prompt"},
                "vars": {"input": "user input"},
                "error": "OpenAI API error: missing key",
                "success": False,
                "failureReason": "GRADER_ERROR",
            }
        ])

        result = collector._extract_rows(df, "test.jsonl")

        assert len(result) == 1
        assert result["latency_ms"].iloc[0] is None
        assert result["cached"].iloc[0] is None
        assert result["http_status"].iloc[0] is None
        assert result["api_response"].iloc[0] == {}
        assert result["error"].iloc[0] == "OpenAI API error: missing key"


class TestClassifyErrors:
    def test_returns_none_for_successful_row_with_http_200(self) -> None:
        df = pd.DataFrame([{"error": None, "failureReason": 0}])
        http = pd.Series([200])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] is None

    def test_returns_http_error_when_status_ge_400_and_no_error_field(self) -> None:
        df = pd.DataFrame([{"failureReason": 1}])
        http = pd.Series([422])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] == "HTTP 422 error"

    def test_returns_http_error_when_status_ge_400_and_numeric_failure_reason(self) -> None:
        df = pd.DataFrame([{"error": "some assertion text", "failureReason": 1}])
        http = pd.Series([500])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] == "HTTP 500 error"

    def test_returns_error_for_string_failure_reason(self) -> None:
        df = pd.DataFrame([{"error": "FileNotFoundError", "failureReason": "GRADER_ERROR"}])
        http = pd.Series([200])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] == "FileNotFoundError"

    def test_returns_none_for_numeric_failure_reason_with_http_200(self) -> None:
        df = pd.DataFrame([{"error": "assertion failed", "failureReason": 1}])
        http = pd.Series([200])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] is None

    def test_returns_none_when_no_error_and_http_200(self) -> None:
        df = pd.DataFrame([{"failureReason": 1}])
        http = pd.Series([200])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] is None

    def test_returns_http_error_for_various_4xx_5xx_codes(self) -> None:
        df = pd.DataFrame([
            {"failureReason": 1},
            {"failureReason": 1},
            {"failureReason": 1},
        ])
        http = pd.Series([400, 403, 503])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] == "HTTP 400 error"
        assert result.iloc[1] == "HTTP 403 error"
        assert result.iloc[2] == "HTTP 503 error"

    def test_handles_nan_http_status(self) -> None:
        df = pd.DataFrame([{"failureReason": 1}])
        http = pd.Series([float("nan")])
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] is None

    def test_handles_none_http_status(self) -> None:
        df = pd.DataFrame([{"failureReason": 1}])
        http = pd.Series([None], dtype=object)
        result = PromptfooResultCollector._classify_errors(df, http)
        assert result.iloc[0] is None


class TestExtractRowsHttpErrorClassification:
    def test_http_422_with_numeric_failure_reason_produces_error(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row(
            http_status=422,
            success=False,
            score=0.0,
            failure_reason=1,
        )])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["error"].iloc[0] == "HTTP 422 error"

    def test_http_200_with_numeric_failure_reason_produces_no_error(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row(
            http_status=200,
            success=False,
            score=0.0,
            failure_reason=1,
        )])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["error"].iloc[0] is None


class TestBuildDataframe:
    def test_concatenates_valid_files_while_ignoring_invalid_ones(self, tmp_path: Path) -> None:
        # Create 3 valid files (3 rows each), 1 invalid JSONL, 1 non-JSONL text file
        for name in ["a.jsonl", "b.jsonl", "c.jsonl"]:
            rows = [json.dumps(_make_jsonl_row()) for _ in range(3)]
            (tmp_path / name).write_text("\n".join(rows) + "\n")
            
        (tmp_path / "bad.jsonl").write_text("not json {{{")
        (tmp_path / "readme.txt").write_text("not data")
        
        collector = _make_collector(tmp_path)
        result = collector.build_dataframe()
        
        # Should only process the 3 valid files containing 3 rows each
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 9

    def test_returns_empty_dataframe_when_no_valid_files_exist(self, tmp_path: Path) -> None:
        result = _make_collector(tmp_path).build_dataframe()

        assert isinstance(result, pd.DataFrame)
        assert len(result) == 0

    def test_includes_errored_rows_in_output(self, tmp_path: Path) -> None:
        rows = [
            json.dumps(_make_jsonl_row()),
            json.dumps(_make_jsonl_row(
                error="Error running Python script: FileNotFoundError",
                failure_reason="GRADER_ERROR",
            )),
        ]
        (tmp_path / "test.jsonl").write_text("\n".join(rows) + "\n")

        result = _make_collector(tmp_path).build_dataframe()

        assert len(result) == 2
        assert result["error"].iloc[0] is None
        assert result["error"].iloc[1] == "Error running Python script: FileNotFoundError"


class TestExtractConversation:
    def test_returns_none_when_no_conversation_in_vars(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row()])
        result = collector._extract_rows(df, "test.jsonl")
        assert result["conversation"].iloc[0] is None

    def test_extracts_conversation_from_vars(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        conversation = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        row = _make_jsonl_row()
        row["vars"]["conversation"] = conversation
        df = pd.DataFrame([row])
        result = collector._extract_rows(df, "test.jsonl")
        assert result["conversation"].iloc[0] == conversation

    def test_extracts_messages_from_vars(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        messages = [
            {"role": "user", "content": "Turn 1"},
            {"role": "assistant", "content": "Response 1"},
        ]
        row = _make_jsonl_row()
        row["vars"]["messages"] = messages
        df = pd.DataFrame([row])
        result = collector._extract_rows(df, "test.jsonl")
        assert result["conversation"].iloc[0] == messages

    def test_returns_none_when_vars_has_no_conversation_keys(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        row = _make_jsonl_row()
        # vars has "input" but no "conversation" or "messages"
        df = pd.DataFrame([row])
        result = collector._extract_rows(df, "test.jsonl")
        assert result["conversation"].iloc[0] is None


def _make_multiturn_response(
    messages: list[dict[str, str]] | None = None,
    successful_attacks: list[dict] | None = None,
    stored_grader_result: dict | None = None,
) -> dict:
    """Build a response dict with multiturn metadata."""
    meta: dict = {}
    if messages is not None:
        meta["messages"] = messages
    if successful_attacks is not None:
        meta["successfulAttacks"] = successful_attacks
    if stored_grader_result is not None:
        meta["storedGraderResult"] = stored_grader_result
    return {
        "raw": {"data": {"valid": False, "reason_code": "test", "duration": 1.0,
                         "extra": {"accept_score": 0.5, "reject_score": 0.5}}},
        "latencyMs": 100,
        "cached": False,
        "metadata": {**meta, "http": {"status": 201}},
    }


class TestExtractMultiturnMetadata:
    def test_extracts_messages_from_response_metadata(self) -> None:
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        resp = pd.Series([_make_multiturn_response(messages=messages)])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["multiturn_messages"].iloc[0] == messages

    def test_extracts_successful_attacks(self) -> None:
        attacks = [{"turn": 2, "prompt": "p", "response": "r"}]
        resp = pd.Series([_make_multiturn_response(successful_attacks=attacks)])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["successful_attacks"].iloc[0] == attacks

    def test_extracts_stored_grader_result(self) -> None:
        grader = {"score": 0, "reason": "bypassed", "pass": False}
        resp = pd.Series([_make_multiturn_response(stored_grader_result=grader)])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["stored_grader_result"].iloc[0] == grader

    def test_returns_none_for_single_turn_rows(self) -> None:
        resp = pd.Series([{
            "raw": {"data": {}},
            "latencyMs": 100,
            "cached": False,
            "metadata": {"http": {"status": 200}},
        }])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["multiturn_messages"].iloc[0] is None
        assert result["successful_attacks"].iloc[0] is None
        assert result["stored_grader_result"].iloc[0] is None

    def test_returns_none_when_response_is_not_dict(self) -> None:
        resp = pd.Series(["not a dict"])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["multiturn_messages"].iloc[0] is None

    def test_returns_none_when_metadata_is_missing(self) -> None:
        resp = pd.Series([{"raw": {}}])
        result = PromptfooResultCollector._extract_multiturn_metadata(resp)
        assert result["multiturn_messages"].iloc[0] is None

    def test_extract_rows_includes_multiturn_columns(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([_make_jsonl_row()])
        result = collector._extract_rows(df, "test.jsonl")
        assert "multiturn_messages" in result.columns
        assert "successful_attacks" in result.columns
        assert "stored_grader_result" in result.columns

    def test_extract_rows_populates_multiturn_columns_for_multiturn_row(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        messages = [
            {"role": "user", "content": "u1"},
            {"role": "assistant", "content": "a1"},
        ]
        attacks = [{"turn": 1, "prompt": "u1", "response": "a1"}]
        grader = {"score": 0, "reason": "bypassed", "pass": False}

        row = _make_jsonl_row()
        row["response"] = _make_multiturn_response(
            messages=messages,
            successful_attacks=attacks,
            stored_grader_result=grader,
        )
        df = pd.DataFrame([row])
        result = collector._extract_rows(df, "test.jsonl")

        assert result["multiturn_messages"].iloc[0] == messages
        assert result["successful_attacks"].iloc[0] == attacks
        assert result["stored_grader_result"].iloc[0] == grader
