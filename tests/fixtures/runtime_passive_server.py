import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        state = self.server.state
        record = {"method": "GET", "path": self.path, "headers": {key.lower(): value for key, value in self.headers.items()}}
        state.append(record)
        print(json.dumps(record), flush=True)
        with open(self.server.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        if self.path == "/redirect-internal":
            self.send_response(302)
            self.send_header("Location", "/page-a")
            self.end_headers()
            return
        if self.path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "https://external.example.invalid/out")
            self.end_headers()
            return
        if self.path == "/protected" and self.headers.get("Authorization") != "Bearer synthetic-passive-token":
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"unauthorized")
            return
        pages = {
            "/": '<html><body><a href="/page-a">page a</a><a href="/protected">protected</a><a href="/redirect-internal">redirect</a><a href="/redirect-external">external</a><a href="https://external.example.invalid/">out</a><form action="/mutate" method="post"></form></body></html>',
            "/page-a": '<html><body><a href="/page-b?item=1">page b</a></body></html>',
            "/page-b": '<html><body>page b</body></html>',
            "/protected": '{"secret":"synthetic"}',
        }
        body = pages.get(self.path.split("?", 1)[0])
        if body is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if self.path == "/protected" else "text/html")
        if self.path == "/page-a":
            self.send_header("Set-Cookie", "fixture_session=synthetic")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    state = []
    server = HTTPServer(("0.0.0.0", args.port), Handler)
    server.state = state
    server.log_path = args.log
    try:
        server.serve_forever()
    finally:
        with open(args.log, "w", encoding="utf-8") as handle:
            json.dump(state, handle)


if __name__ == "__main__":
    main()
