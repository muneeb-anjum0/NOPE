from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/debug":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"debug": true, "public_api": true}')
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", params.get("next", ["https://example.com"])[0])
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=fixture")
        self.end_headers()
        name = params.get("name", ["world"])[0]
        self.wfile.write(f"<html><body>Hello {name}</body></html>".encode("utf-8"))


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
