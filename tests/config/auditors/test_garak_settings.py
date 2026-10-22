import pytest

from pentester.config.auditors.garak_settings import GarakSettings


class TestDefaults:
    def test_probes_default(self) -> None:
        assert GarakSettings().probes == []

    def test_max_attacks_default_is_none(self) -> None:
        assert GarakSettings().max_attacks is None

    def test_parallel_attempts_default_is_sequential(self) -> None:
        assert GarakSettings().parallel_attempts == 1

    def test_max_retries_default(self) -> None:
        assert GarakSettings().max_retries == 3

    def test_judge_model_default_is_none(self) -> None:
        assert GarakSettings().judge_model is None


class TestDirectInit:
    def test_set_probes(self) -> None:
        settings = GarakSettings(probes=["probes.dan"])
        assert settings.probes == ["probes.dan"]

    def test_set_max_attacks(self) -> None:
        settings = GarakSettings(max_attacks=50)
        assert settings.max_attacks == 50

    def test_max_attacks_none_accepted(self) -> None:
        settings = GarakSettings(max_attacks=None)
        assert settings.max_attacks is None

    def test_set_parallel_attempts(self) -> None:
        assert GarakSettings(parallel_attempts=8).parallel_attempts == 8


class TestValidation:
    def test_parallel_attempts_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="parallel_attempts must be at least 1"):
            GarakSettings(parallel_attempts=0)

    def test_max_retries_zero_accepted(self) -> None:
        assert GarakSettings(max_retries=0).max_retries == 0

    def test_max_retries_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_retries must be at least 0"):
            GarakSettings(max_retries=-1)

    def test_parallel_attempts_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="parallel_attempts must be at least 1"):
            GarakSettings(parallel_attempts=-3)


class TestJudgeModel:
    def test_provider_and_model_accepted(self) -> None:
        settings = GarakSettings(judge_model="deepseek/deepseek-chat")
        assert settings.judge_model == "deepseek/deepseek-chat"

    def test_model_with_slashes_accepted(self) -> None:
        settings = GarakSettings(judge_model="openai/org/model")
        assert settings.judge_model == "openai/org/model"

    def test_empty_string_means_unset(self) -> None:
        assert GarakSettings(judge_model="").judge_model is None

    def test_missing_provider_rejected(self) -> None:
        with pytest.raises(ValueError, match="judge_model must be"):
            GarakSettings(judge_model="deepseek-chat")

    def test_unknown_provider_rejected(self) -> None:
        with pytest.raises(ValueError, match="judge_model must be"):
            GarakSettings(judge_model="nim/meta/llama3-70b-instruct")

    def test_missing_model_rejected(self) -> None:
        with pytest.raises(ValueError, match="judge_model must be"):
            GarakSettings(judge_model="deepseek/")


class TestEnvVarOverrides:
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "100")
        settings = GarakSettings()
        assert settings.max_attacks == 100

    def test_parallel_attempts_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PARALLEL_ATTEMPTS", "16")
        assert GarakSettings().parallel_attempts == 16

    def test_judge_model_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JUDGE_MODEL", "deepseek/deepseek-chat")
        assert GarakSettings().judge_model == "deepseek/deepseek-chat"
