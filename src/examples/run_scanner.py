from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import (
    UncurlHandler,
)
from pentester.scanners.scanner import Scanner

curl_command = """curl https://api.openai.com/v1/chat/completions \
-H "Content-Type: application/json" \
-H "Authorization: <API_KEY>" \
-d '{{
"model": "gpt-4o-mini",
"messages": [
    {{
        "role": "user",
        "content": $PROMPT
    }}
]
}}'"""

serializer = JSONDotSerializer(target="body.choices.0.message.content")
handler = UncurlHandler(
    curl_command=curl_command,
    response_serializer=serializer,
)
scan = Scanner(handler).scan("Is this a test?")
print(scan.response)
