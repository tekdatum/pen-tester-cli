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
) -> dict:
    return {
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
    }


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
            "strategy_id", "plugin_id",
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

    def test_handles_missing_nested_keys_gracefully(self) -> None:
        collector = PromptfooResultCollector(results_path=Path("/tmp"))
        df = pd.DataFrame([{"provider": {}, "prompt": {}, "vars": {}, "response": {}}])

        result = collector._extract_rows(df, "test.jsonl")

        assert result["provider_url"].iloc[0] is None
        assert result["prompt"].iloc[0] is None
        assert result["strategy_id"].iloc[0] is None
        assert result["plugin_id"].iloc[0] is None


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