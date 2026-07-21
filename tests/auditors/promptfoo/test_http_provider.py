import pytest
from pydantic import ValidationError

from pentester.auditors.promptfoo.http_provider import PromptfooHTTPProvider


def _make_provider(**kwargs: object) -> PromptfooHTTPProvider:
    defaults: dict[str, object] = {"url": "http://example.com/api"}
    defaults.update(kwargs)
    return PromptfooHTTPProvider(**defaults)


class TestInitialization:
    def test_initializes_with_defaults(self) -> None:
        provider = _make_provider()

        assert provider.method == "POST"
        assert provider.headers == {}
        assert provider.timeout == 5000
        assert provider.body_template == "{{prompt}}"
        assert provider.response_parser is None

    def test_initializes_with_explicit_arguments(self) -> None:
        headers = {"Authorization": "Bearer token"}
        provider = _make_provider(
            url="http://my-api.com",
            method="GET",
            headers=headers,
            timeout=10000,
            body_template="{{input}}",
            response_parser="json.data.text",
        )

        assert provider.url == "http://my-api.com"
        assert provider.method == "GET"
        assert provider.headers == headers
        assert provider.timeout == 10000
        assert provider.body_template == "{{input}}"
        assert provider.response_parser == "json.data.text"

    def test_raises_error_if_url_is_missing(self) -> None:
        with pytest.raises(ValidationError):
            PromptfooHTTPProvider()  # type: ignore[call-arg]


class TestTransformConfig:
    def test_transforms_promptfoo_config_keys(self) -> None:
        provider = PromptfooHTTPProvider(
            url="http://example.com",
            body={"text": "custom {{prompt}}"},
            responseParser="json.choices[0].text",
        )

        assert provider.body_template == "custom {{prompt}}"
        assert provider.response_parser == "json.choices[0].text"

    def test_ignores_invalid_body_structures(self) -> None:
        # If 'body' isn't a dict with a 'text' key, it should fall back to the default
        p1 = PromptfooHTTPProvider(url="http://example.com", body={"other": "value"})
        p2 = PromptfooHTTPProvider(url="http://example.com", body="raw string")
        p3 = PromptfooHTTPProvider(url="http://example.com", body=123)

        assert p1.body_template == "{{prompt}}"
        assert p2.body_template == "{{prompt}}"
        assert p3.body_template == "{{prompt}}"

    def test_body_text_overrides_explicit_body_template(self) -> None:
        provider = PromptfooHTTPProvider(
            url="http://example.com",
            body={"text": "from body"},
            body_template="explicit",
        )

        # Pydantic's pre-validators run before field assignment, meaning
        # the transformed 'body' takes precedence over 'body_template'
        assert provider.body_template == "from body"


class TestStringRepresentation:
    def test_string_contains_all_fields_and_values(self) -> None:
        provider = _make_provider(url="http://my-api.com", method="GET", timeout=9999)
        output = str(provider)

        # Parse "LABEL: value" lines and compare values exactly rather than
        # via substring checks, which are weaker and trip CodeQL's
        # incomplete-url-substring-sanitization heuristic.
        parsed = dict(line.split(": ", 1) for line in output.splitlines())

        assert parsed["URL"] == "http://my-api.com"
        assert parsed["METHOD"] == "GET"
        assert parsed["HEADERS"] == "{}"
        assert parsed["TIMEOUT"] == "9999"
        assert parsed["BODY_TEMPLATE"] == "{{prompt}}"
        assert parsed["RESPONSE_PARSER"] == "None"
