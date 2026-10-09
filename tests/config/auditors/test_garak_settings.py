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


class TestEnvVarOverrides:
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "100")
        settings = GarakSettings()
        assert settings.max_attacks == 100

    def test_parallel_attempts_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PARALLEL_ATTEMPTS", "16")
        assert GarakSettings().parallel_attempts == 16
