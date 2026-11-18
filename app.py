"""
app.py - the web server (Python standard library only).

    GET  /              the dashboard
    GET  /api/dfas      the automata, as nodes/edges for the diagrams
    POST /scan          JSON {"text": "..."}  ->  redaction result + token traces
    POST /redact-file   raw file bytes (?name=report.csv) -> redacted file download
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from engine import PIIAutomatonEngine

HOST, PORT = "127.0.0.1", 5000
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".txt", ".csv", ".tsv", ".log", ".json", ".md"}
DASHBOARD = Path(__file__).with_name("dashboard.html")

engine = PIIAutomatonEngine()
AUTOMATA_JSON = json.dumps(engine.describe_automata()).encode("utf-8")


def safe_download_name(name: str) -> str:
    """report.csv -> report.redacted.csv (path parts and odd characters removed)."""
    path = Path(Path(name).name)
    stem = "".join(c for c in path.stem if c.isalnum() or c in "-_ ") or "file"
    return f"{stem}.redacted{path.suffix.lower()}"


class RequestHandler(BaseHTTPRequestHandler):
    def _send(self, status, body=b"", content_type="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, message):
        self._send(status, json.dumps({"error": message}).encode("utf-8"))

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_UPLOAD_BYTES:
            self._error(413, "File too large (limit 5 MB).")
            return None
        return self.rfile.read(length)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, DASHBOARD.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/dfas":
            self._send(200, AUTOMATA_JSON)
        else:
            self._error(404, "Not found")

    def do_POST(self):
        url = urlparse(self.path)
        body = self._read_body()
        if body is None:
            return

        if url.path == "/scan":
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
            except (ValueError, UnicodeDecodeError):
                return self._error(400, "Body must be valid JSON.")
            result = engine.process_text(str(payload.get("text", "")))
            self._send(200, json.dumps(result).encode("utf-8"))

        elif url.path == "/redact-file":
            name = parse_qs(url.query).get("name", ["file.txt"])[0]
            if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
                return self._error(400, "Unsupported file type.")
            result = engine.process_text(body.decode("utf-8", errors="replace"))
            self._send(200, result["redacted_text"].encode("utf-8"), "text/plain; charset=utf-8", {
                "Content-Disposition": f'attachment; filename="{safe_download_name(name)}"',
                "X-PII-Count": str(result["pii_count"]),
                "Access-Control-Expose-Headers": "X-PII-Count, Content-Disposition",
            })
        else:
            self._error(404, "Not found")


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), RequestHandler)
    print(f"Server active at http://{HOST}:{PORT}")
    server.serve_forever()