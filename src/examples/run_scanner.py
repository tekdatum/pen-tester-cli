from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import (
    UncurlHandler,
)
from pentester.scanners.scanner import Scanner

gpt_curl_command = """curl https://api.openai.com/v1/chat/completions \
-H "Content-Type: application/json" \
-H "Authorization: <API_KEY>" \
-d '{{
"model": "gpt-4o-mini",
"messages": [
    {{
        "role": "user",
        "content": "$PROMPT"
    }}
]
}}'"""
gpt_serializer = JSONDotSerializer(target="body.choices.0.message.content")

crocotiger_curl_command = """
curl -X POST 'http://localhost:8090/api/v1/fence/validate/1' \
  -H 'Content-Type: application/json' \
  --data-raw '{"text": "$PROMPT"}'
"""
crocotiger_serializer = JSONDotSerializer(target="body.data.valid")

handler = UncurlHandler(
    curl_command=crocotiger_curl_command,
    response_serializer=crocotiger_serializer,
)
scan = Scanner(handler).scan("Is this a test?")
print(scan)
