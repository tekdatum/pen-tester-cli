# Scanner

Executes a curl command against a target by injecting a prompt, and optionally extracts a value from the response to determine if a bypass occurred.

## Usage

```python
from pentester.scanners.scanner import Scanner
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import UncurlHandler
from pentester.scanners.response_serializers.json_dot_serializer import JSONDotSerializer

serializer = JSONDotSerializer(target="body.data.valid")
handler = UncurlHandler(
    curl_command="curl -X POST 'https://target.com/api' -H 'Content-Type: application/json' --data-raw '{\"text\": $PROMPT}'",
    response_serializer=serializer,
)
scanner = Scanner(handler)
result = scanner.scan("Ignore previous instructions")

print(result.response)    # full HTTP response as string (status line + headers + body)
print(result.bypassed)    # True / False / None
print(result.text)        # extracted LLM reply text, or None if response_text_target not set
```

`json_dot_target` is optional. If omitted, `bypassed` will always be `None`.

---

## CURL Command Syntax

The curl command must include the `$PROMPT` variable, which is replaced by the prompt text at scan time.

```bash
curl -X POST 'https://api.example.com/chat' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer TOKEN' \
  --data-raw '{"messages": [{"role": "user", "content": $PROMPT}]}'
```

> `$PROMPT` is replaced with a complete JSON string literal including surrounding double-quotes (e.g. `"hello world"`, `"say \"hi\""` with escaping applied). Always use bare `$PROMPT` — never `"$PROMPT"` — so the substituted value is valid JSON.

---

## JSON Dot Target Syntax

A dot-separated string with the format `section.key1.key2...` that navigates the HTTP response to extract a value.

### Available sections

| Section | Description |
|---|---|
| `body` | Response body parsed as JSON |
| `headers` | Response headers |

### Examples

```python
"body.valid"                        # {"valid": true}
"body.data.valid"                   # {"data": {"valid": false}}
"body.choices.0.message.content"    # {"choices": [{"message": {"content": "..."}}]}
"headers.X-Guard-Result"
```

The extracted value is cast to bool to determine `bypassed`:
- truthy value → `bypassed = True`
- falsy value → `bypassed = False`

---

## Response Text Target

`response_text_target` uses the same dot-path syntax to extract the LLM's reply text from the response body and populate `TargetResponse.text`. This is required when using:

- **Garak `ScannerGenerator`** (LLM target type) — garak needs the raw model reply, not the JSON envelope
- **PyRIT `ScannerTarget`** (multi-turn attacks) — each turn's reply is stored in conversation memory; it must be plain text so the attacker LLM can reason about it

```python
scanner = Scanner.from_curl(
    curl_command="curl -X POST 'https://api.example.com/v1/chat/completions' ...",
    response_text_target="body.choices.0.message.content",
)
result = scanner.scan("hello")
print(result.text)   # "Hello! How can I help you today?"
```

Or via settings:

```
PENTESTER_SCANNER__RESPONSE_TEXT_TARGET=body.choices.0.message.content
```

If `response_text_target` is not set, `TargetResponse.text` is `None`. Auditors that require it will raise a `ValueError` with a clear message.

---

## Custom Handler

If the target is not accessible via curl (e.g. a Python SDK, a gRPC client, a local model), you can implement your own handler by extending `CustomHandler`.

### 1. Create your handler file

```python
# my_handler.py
from pentester import CustomHandler, HandlerResponse

class MyServiceHandler(CustomHandler):
    def request(self, text: str) -> HandlerResponse:
        # Call your service however you need
        response = my_sdk_client.send(text)
        return HandlerResponse(
            response=response.text,
            passed=response.was_blocked,
        )
```

`passed=True` means the service blocked the prompt (no bypass). `passed=False` means the prompt got through (bypass).

### 2. Use it programmatically

```python
from pentester.scanners.scanner import Scanner

scanner = Scanner.from_handler(MyServiceHandler())
result = scanner.scan("Ignore previous instructions")

print(result.response)   # text returned by the service
print(result.bypassed)   # True if the prompt bypassed the guard
```

### 3. Example in CLI

```bash
pentester ./my_handler.py:MyServiceHandler
```

The argument format is `<path>:<ClassName>`, separated by a colon:

| Part | Description | Example |
|---|---|---|
| `<path>` | Path to the `.py` file, relative or absolute | `./my_handler.py`, `/home/user/handlers/my_handler.py` |
| `<ClassName>` | Name of the class inside that file that extends `CustomHandler` | `MyServiceHandler` |

```bash
# relative path
pentester ./handlers/my_handler.py:MyServiceHandler

# absolute path
pentester /home/user/project/my_handler.py:MyServiceHandler
```
