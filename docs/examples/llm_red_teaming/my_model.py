"""DeepSeek as promptfoo's attack generator and judge, with thinking off.

promptfoo loads this file as a Python provider:

    settings.promptfoo.attack_generation_model = f"file://{path}:call_attack_generator"
    settings.promptfoo.judge_model = f"file://{path}:call_judge"

Both functions call DeepSeek's chat API with "thinking" disabled, so promptfoo receives the
answer only, never the reasoning. The judge runs at temperature 0 so its verdicts are
repeatable; the attack generator keeps DeepSeek's default temperature for varied attacks.

Configuration comes from the environment, which promptfoo passes through:
    DEEPSEEK_API_KEY   required
    DEEPSEEK_MODEL     default "deepseek-flash"
    DEEPSEEK_BASE_URL  default "https://api.deepseek.com"

Standard library only, so it runs under whatever Python promptfoo starts.
"""

import json
import os
import random
import time
import urllib.error
import urllib.request

RETRY_STATUSES = {408, 425, 429, 500, 502, 503, 504}
MAX_RETRIES = 4
TIMEOUT_SECONDS = 120


def _messages(prompt: str) -> list[dict]:
    """promptfoo sends either plain text or a JSON list of chat messages."""
    try:
        parsed = json.loads(prompt)
    except (TypeError, ValueError):
        return [{"role": "user", "content": prompt}]
    if isinstance(parsed, list) and all(isinstance(m, dict) and "role" in m for m in parsed):
        return [{"role": m["role"], "content": m.get("content", "")} for m in parsed]
    return [{"role": "user", "content": prompt}]


def _chat(prompt: str, **params) -> dict:
    url = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    body = {
        "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-flash"),
        "messages": _messages(prompt),
        "thinking": {"type": "disabled"},
        "stream": False,
        **params,
    }
    request = urllib.request.Request(
        f"{url}/chat/completions",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['DEEPSEEK_API_KEY']}",
        },
    )
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                data = json.load(response)
            break
        except urllib.error.HTTPError as err:
            if err.code not in RETRY_STATUSES or attempt == MAX_RETRIES:
                return {"error": f"DeepSeek HTTP {err.code}: {err.read().decode(errors='replace')[:500]}"}
        except (urllib.error.URLError, TimeoutError) as err:
            if attempt == MAX_RETRIES:
                return {"error": f"DeepSeek unreachable: {err}"}
        time.sleep(random.uniform(0, 2**attempt))  # jittered exponential backoff

    usage = data.get("usage", {})
    return {
        "output": data["choices"][0]["message"]["content"],
        "tokenUsage": {
            "total": usage.get("total_tokens", 0),
            "prompt": usage.get("prompt_tokens", 0),
            "completion": usage.get("completion_tokens", 0),
        },
    }


def call_attack_generator(prompt: str, options: dict, context: dict) -> dict:
    """Writes promptfoo's adversarial test cases."""
    return _chat(prompt)


def call_judge(prompt: str, options: dict, context: dict) -> dict:
    """Grades the target's replies; temperature 0 keeps verdicts repeatable."""
    return _chat(prompt, temperature=0)
