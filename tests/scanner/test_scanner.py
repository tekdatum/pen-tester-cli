from unittest.mock import MagicMock
from pentester.scanners.scanner import Scanner
from pentester.scanners.request_handlers.curl_handlers.uncurl_handler import UncurlHandler
from pentester.scanners.response_serializers.json_dot_serializer import JSONDotSerializer

CURL_COMMAND = """
curl -X POST 'http://localhost:8090/api/v1/fence/validate/1'
-H 'Content-Type: application/json'
--data-raw '{"text": $PROMPT}'
"""
PROMPT = "Can I take vacations?"

def test_scanner():
    serializer = JSONDotSerializer(target="body.data.valid")
    handler = UncurlHandler(curl_command=CURL_COMMAND, response_serializer=serializer)
    scanner = Scanner(handler)
    response = scanner.scan(PROMPT)
    print(response)