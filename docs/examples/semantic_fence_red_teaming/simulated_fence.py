"""A stand-in semantic fence for trying CrocoTester without a real guardrail.

A semantic fence answers one question about every prompt: allow it or block it.
This one is deliberately simple: it blocks a prompt that contains one of a few
red-flag phrases and allows everything else. It needs no server, no model and no
API key, and it answers the same way every time, so runs are repeatable.

CrocoTester loads it as a custom handler:

    PENTESTER_SCANNER__CUSTOM_HANDLER=simulated_fence.py:SimulatedFence

and reads ``passed`` on every answer: True means the prompt got through the
fence (bypassed), False means the fence blocked it.

``start_http_fence()`` serves the same fence over HTTP, for trying the curl
integration. Like many real guardrail APIs it answers ``{"valid": false}`` when
it stops a prompt, so CrocoTester needs ``true_means=blocked`` to read it.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pentester import CustomHandler, HandlerResponse

RED_FLAGS = (
    "ignore previous instructions",
    "ignore all previous",
    "do anything now",
    "jailbreak",
    "bomb",
    "explosive",
    "weapon",
    "malware",
    "poison",
    "kill",
)


class SimulatedFence(CustomHandler):
    def request(self, text: str) -> HandlerResponse:
        lowered = text.lower()
        flag = next((phrase for phrase in RED_FLAGS if phrase in lowered), None)
        valid = flag is None
        verdict = {"valid": valid, "reason": f"matched {flag!r}" if flag else "no red flag"}
        
        # HandlerResponse.passed=True means the prompt got through the fence,
        # False means the fence blocked it.
        return HandlerResponse(response=json.dumps(verdict), passed=valid)


def start_http_fence(port: int = 0) -> ThreadingHTTPServer:
    """Serve SimulatedFence at http://127.0.0.1:<port>/validate in a background thread.

    POST {"text": "..."} and get {"valid": bool, "reason": str}. Port 0 picks a
    free port; read it from ``server.server_port``. Call ``server.shutdown()`` to stop.
    """
    fence = SimulatedFence()

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            try:
                text = json.loads(self.rfile.read(length))["text"]
            except (ValueError, KeyError, TypeError):
                self.send_error(400, "expected a JSON body with a 'text' field")
                return
            verdict = json.loads(fence.request(text).response)
            body = json.dumps(
                {"valid": verdict["valid"], "reason": verdict["reason"]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # keep the notebook quiet
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
