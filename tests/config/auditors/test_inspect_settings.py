import pytest

from pentester.config.auditors.inspect_settings import InspectSettings


class TestDefaults:
    def test_evals_default(self) -> None:
        assert InspectSettings().evals == []

    def test_limit_default_is_none(self) -> None:
        assert InspectSettings().limit is None

    def test_epochs_default(self) -> None:
        assert InspectSettings().epochs == 1

    def test_judge_model_default(self) -> None:
        assert InspectSettings().judge_model == "openai/gpt-4o"

    def test_max_attacks_default_is_none(self) -> None:
        assert InspectSettings().max_attacks is None


class TestDirectInit:
    def test_set_evals(self) -> None:
        settings = InspectSettings(evals=["strong_reject"])
        assert settings.evals == ["strong_reject"]

    def test_set_limit(self) -> None:
        settings = InspectSettings(limit=100)
        assert settings.limit == 100

    def test_set_epochs(self) -> None:
        settings = InspectSettings(epochs=3)
        assert settings.epochs == 3

    def test_set_judge_model(self) -> None:
        settings = InspectSettings(judge_model="openai/gpt-4o-mini")
        assert settings.judge_model == "openai/gpt-4o-mini"

    def test_set_max_attacks(self) -> None:
        settings = InspectSettings(max_attacks=200)
        assert settings.max_attacks == 200

    def test_max_attacks_none_accepted(self) -> None:
        settings = InspectSettings(max_attacks=None)
        assert settings.max_attacks is None


class TestEnvVarOverrides:
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "75")
        settings = InspectSettings()
        assert settings.max_attacks == 75
