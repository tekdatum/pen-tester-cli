from pentester.scanners.models.target_response import TargetResponse


# ── TargetResponse.duration ───────────────────────────────────────────────────


def test_duration_defaults_to_none() -> None:
    assert TargetResponse(response="ok", bypassed=None).duration is None


def test_duration_can_be_set() -> None:
    assert TargetResponse(response="ok", bypassed=None, duration=1.23).duration == 1.23
