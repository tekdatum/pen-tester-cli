import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

import pytest
from requests import ConnectionError, HTTPError, Response, Timeout

from pentester.utils.retry import (
    RetryCancelled,
    backoff_delay,
    is_transient,
    retry_after_seconds,
    with_retries,
)


def _make_http_error(status_code: int, retry_after: str | None = None) -> HTTPError:
    response = Response()
    response.status_code = status_code
    if retry_after is not None:
        response.headers["Retry-After"] = retry_after
    return HTTPError(response=response)


def _make_cancel(set_before: bool = False, set_during_wait: bool = False) -> MagicMock:
    """Stand-in for threading.Event: is_set() and wait() return fixed answers."""
    cancel = MagicMock()
    cancel.is_set.return_value = set_before
    cancel.wait.return_value = set_during_wait
    return cancel


class TestIsTransient:
    @pytest.mark.parametrize("status", [408, 425, 429, 502, 503, 504])
    def test_retryable_status_is_transient(self, status: int) -> None:
        assert is_transient(_make_http_error(status)) is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 500])
    def test_other_status_is_not_transient(self, status: int) -> None:
        assert is_transient(_make_http_error(status)) is False

    def test_connection_error_is_transient(self) -> None:
        assert is_transient(ConnectionError()) is True

    def test_timeout_is_transient(self) -> None:
        assert is_transient(Timeout()) is True

    def test_http_error_without_response_is_not_transient(self) -> None:
        assert is_transient(HTTPError()) is False

    def test_generic_exception_is_not_transient(self) -> None:
        assert is_transient(ValueError("bad payload")) is False


class TestRetryAfterSeconds:
    def test_none_without_response(self) -> None:
        assert retry_after_seconds(ValueError()) is None

    def test_none_without_header(self) -> None:
        assert retry_after_seconds(_make_http_error(429)) is None

    def test_parses_seconds(self) -> None:
        assert retry_after_seconds(_make_http_error(429, "7")) == 7.0

    def test_negative_seconds_clamped_to_zero(self) -> None:
        assert retry_after_seconds(_make_http_error(429, "-3")) == 0.0

    def test_parses_http_date(self) -> None:
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        delay = retry_after_seconds(_make_http_error(429, format_datetime(retry_at)))
        assert delay is not None and 25 <= delay <= 30

    def test_naive_http_date_treated_as_utc(self) -> None:
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        header = retry_at.strftime("%a, %d %b %Y %H:%M:%S -0000")
        delay = retry_after_seconds(_make_http_error(429, header))
        assert delay is not None and 25 <= delay <= 30

    def test_past_http_date_clamped_to_zero(self) -> None:
        header = "Wed, 21 Oct 2015 07:28:00 GMT"
        assert retry_after_seconds(_make_http_error(429, header)) == 0.0

    def test_unparseable_header_returns_none(self) -> None:
        assert retry_after_seconds(_make_http_error(429, "soon")) is None


class TestBackoffDelay:
    def test_retry_after_takes_precedence(self) -> None:
        exc = _make_http_error(429, "4")
        assert backoff_delay(exc, attempt=0, base_delay=1.0, max_delay=60.0) == 4.0

    def test_retry_after_capped_at_max_delay(self) -> None:
        exc = _make_http_error(429, "600")
        assert backoff_delay(exc, attempt=0, base_delay=1.0, max_delay=60.0) == 60.0

    def test_jitter_draws_from_exponential_window(self) -> None:
        with patch("pentester.utils.retry.random.uniform", return_value=1.5) as m:
            backoff_delay(Timeout(), attempt=3, base_delay=1.0, max_delay=60.0)
        m.assert_called_once_with(0, 8.0)

    def test_jitter_window_capped_at_max_delay(self) -> None:
        with patch("pentester.utils.retry.random.uniform", return_value=1.5) as m:
            backoff_delay(Timeout(), attempt=10, base_delay=1.0, max_delay=60.0)
        m.assert_called_once_with(0, 60.0)

    def test_returns_jittered_value(self) -> None:
        with patch("pentester.utils.retry.random.uniform", return_value=0.42):
            assert backoff_delay(Timeout(), 0, 1.0, 60.0) == 0.42


class TestWithRetries:
    @pytest.fixture(autouse=True)
    def _silence_logger(self) -> None:  # type: ignore[misc]
        with patch("pentester.utils.retry.logger"):
            yield

    def test_returns_result_on_success(self) -> None:
        func = MagicMock(return_value="ok")
        assert with_retries(func, max_retries=3, cancel=_make_cancel())("p") == "ok"

    def test_passes_prompt_through(self) -> None:
        func = MagicMock(return_value="ok")
        with_retries(func, max_retries=3, cancel=_make_cancel())("the prompt")
        func.assert_called_once_with("the prompt")

    def test_retries_transient_then_succeeds(self) -> None:
        func = MagicMock(side_effect=[Timeout(), Timeout(), "ok"])
        assert with_retries(func, max_retries=3, cancel=_make_cancel())("p") == "ok"

    def test_gives_up_after_max_retries(self) -> None:
        func = MagicMock(side_effect=Timeout())
        with pytest.raises(Timeout):
            with_retries(func, max_retries=2, cancel=_make_cancel())("p")
        assert func.call_count == 3

    def test_zero_retries_calls_once(self) -> None:
        func = MagicMock(side_effect=Timeout())
        with pytest.raises(Timeout):
            with_retries(func, max_retries=0, cancel=_make_cancel())("p")
        assert func.call_count == 1

    def test_non_transient_error_not_retried(self) -> None:
        func = MagicMock(side_effect=_make_http_error(500))
        with pytest.raises(HTTPError):
            with_retries(func, max_retries=3, cancel=_make_cancel())("p")
        assert func.call_count == 1

    def test_waits_between_attempts(self) -> None:
        cancel = _make_cancel()
        func = MagicMock(side_effect=[_make_http_error(429, "2"), "ok"])
        with_retries(func, max_retries=3, cancel=cancel)("p")
        cancel.wait.assert_called_once_with(2.0)

    def test_without_cancel_waits_on_private_event(self) -> None:
        with patch("pentester.utils.retry.threading.Event") as mock_event:
            mock_event.return_value = _make_cancel()
            func = MagicMock(side_effect=[_make_http_error(429, "2"), "ok"])
            with_retries(func, max_retries=3)("p")
        mock_event.return_value.wait.assert_called_once_with(2.0)

    def test_logs_each_retry(self) -> None:
        func = MagicMock(side_effect=[Timeout(), Timeout(), "ok"])
        with patch("pentester.utils.retry.logger") as mock_logger:
            with_retries(func, max_retries=3, cancel=_make_cancel())("p")
        assert mock_logger.warning.call_count == 2


class TestWithRetriesCancel:
    @pytest.fixture(autouse=True)
    def _silence_logger(self) -> None:  # type: ignore[misc]
        with patch("pentester.utils.retry.logger"):
            yield

    def test_cancel_before_call_raises(self) -> None:
        with pytest.raises(RetryCancelled):
            with_retries(MagicMock(), max_retries=3, cancel=_make_cancel(True))("p")

    def test_cancel_before_call_skips_func(self) -> None:
        func = MagicMock()
        with pytest.raises(RetryCancelled):
            with_retries(func, max_retries=3, cancel=_make_cancel(True))("p")
        func.assert_not_called()

    def test_cancel_during_wait_raises(self) -> None:
        func = MagicMock(side_effect=Timeout())
        cancel = _make_cancel(set_during_wait=True)
        with pytest.raises(RetryCancelled):
            with_retries(func, max_retries=3, cancel=cancel)("p")

    def test_cancel_during_wait_stops_retrying(self) -> None:
        func = MagicMock(side_effect=Timeout())
        cancel = _make_cancel(set_during_wait=True)
        with pytest.raises(RetryCancelled):
            with_retries(func, max_retries=3, cancel=cancel)("p")
        assert func.call_count == 1

    def test_cancel_during_wait_chains_last_failure(self) -> None:
        failure = Timeout()
        cancel = _make_cancel(set_during_wait=True)
        with pytest.raises(RetryCancelled) as excinfo:
            with_retries(MagicMock(side_effect=failure), 3, cancel=cancel)("p")
        assert excinfo.value.__cause__ is failure

    def test_unset_cancel_checked_before_each_attempt(self) -> None:
        cancel = _make_cancel()
        func = MagicMock(side_effect=[Timeout(), "ok"])
        with_retries(func, max_retries=3, cancel=cancel)("p")
        assert cancel.is_set.call_count == 2

    def test_real_event_set_mid_wait_ends_wait(self) -> None:
        # A real Event: the 60s backoff must end as soon as another thread
        # sets it, not after the full delay.
        cancel = threading.Event()
        timer = threading.Timer(0.05, cancel.set)
        func = MagicMock(side_effect=_make_http_error(429, "60"))
        timer.start()
        started = time.monotonic()
        with pytest.raises(RetryCancelled):
            with_retries(func, max_retries=3, cancel=cancel)("p")
        assert time.monotonic() - started < 5
