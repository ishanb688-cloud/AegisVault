"""
server.py
----------
Lightweight web server for AegisVault.
Serves index.html at http://127.0.0.1:8080 and exposes REST API endpoints
backed by the Python security modules.

Usage:
    python server.py
"""

import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from dictionary_generator import build_personal_wordlist
from hash_tools import parse_shadow_line, identify_raw_hash
from bruteforce_simulator import hash_value, dictionary_attack, estimate_time_to_crack
from strength_analyzer import rate_password


class AegisVaultHandler(SimpleHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            return self._send_json({"status": "online", "suite": "AegisVault Web"})
        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError:
            return self._send_json({"error": "Invalid JSON payload"}, status=400)

        if self.path == "/api/wordlist":
            words = build_personal_wordlist(
                name=data.get("name"),
                dob=data.get("dob"),
                pet=data.get("pet"),
                extra_words=data.get("extra_words", []),
            )
            return self._send_json({"count": len(words), "wordlist": words})

        if self.path == "/api/analyze":
            password = data.get("password", "")
            return self._send_json(rate_password(password))

        if self.path == "/api/hash-inspect":
            lines = data.get("lines", [])
            parsed = []
            for line in lines:
                entry = parse_shadow_line(line)
                if entry:
                    parsed.append(entry)
                elif line.strip():
                    parsed.append({"raw": line.strip(), "type": identify_raw_hash(line.strip())})
            return self._send_json({"entries": parsed})

        if self.path == "/api/simulate":
            secret = data.get("secret", "ishan123")
            wordlist = data.get("wordlist", [])
            target = hash_value(secret, algo="sha256")
            res = dictionary_attack(target, wordlist)
            res["estimate"] = estimate_time_to_crack(charset_size=94, length=len(secret))
            return self._send_json(res)

        return self._send_json({"error": "Endpoint not found"}, status=404)


def run_server(host="0.0.0.0", port=None):
    os.chdir(os.path.dirname(os.path.abspath(__file__)) or ".")
    bind_port = int(os.environ.get("PORT", port or 8080))
    server = ThreadingHTTPServer((host, bind_port), AegisVaultHandler)
    print(f"AegisVault running live at http://{host}:{bind_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down AegisVault web server.")
        server.server_close()


if __name__ == "__main__":
    run_server()