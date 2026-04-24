from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os


FINGERPRINT_HEADERS = ("x-ja4t", "x-ja4", "x-ja4one")
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("DEMO_BACKEND_PORT", "5678"))


def fingerprint_snapshot(headers):
    return {name: headers.get(name, "not present") for name in FINGERPRINT_HEADERS}


def request_snapshot(handler):
    headers = {name.lower(): value for name, value in handler.headers.items()}
    return {
        "method": handler.command,
        "path": handler.path,
        "headers": headers,
        "fingerprints": fingerprint_snapshot(headers),
        "client_address": handler.client_address[0],
    }


def render_header_rows(headers):
    rows = []
    for name in sorted(headers):
        value = headers[name]
        rows.append(
            f"<tr><th>{escape(name)}</th><td>{escape(value)}</td></tr>"
        )
    return "".join(rows)


def render_fingerprint_cards(snapshot):
    cards = []
    for name in FINGERPRINT_HEADERS:
        value = snapshot["fingerprints"][name]
        status_class = "present" if value != "not present" else "missing"
        cards.append(
            "<article class='card {status}'>"
            "<h2>{title}</h2>"
            "<code>{value}</code>"
            "</article>".format(
                status=status_class,
                title=escape(name.upper()),
                value=escape(value),
            )
        )
    return "".join(cards)


def render_html(snapshot):
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>fingerprint-proxy local demo</title>
    <style>
      :root {{
        --bg: #f4efe6;
        --panel: #fffaf1;
        --ink: #1f1a17;
        --muted: #6c625c;
        --accent: #0e6b5c;
        --accent-soft: #d8eee6;
        --warn: #a63d40;
        --warn-soft: #f7d9da;
        --line: #d9cfc5;
        --shadow: 0 18px 48px rgba(31, 26, 23, 0.08);
      }}

      * {{
        box-sizing: border-box;
      }}

      body {{
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top left, #efe4d3 0, transparent 28rem),
          linear-gradient(135deg, #f7f1e7 0%, #f0e7da 100%);
      }}

      main {{
        max-width: 1100px;
        margin: 0 auto;
        padding: 32px 20px 56px;
      }}

      .hero {{
        background: rgba(255, 250, 241, 0.9);
        border: 1px solid rgba(217, 207, 197, 0.85);
        border-radius: 24px;
        box-shadow: var(--shadow);
        padding: 28px;
      }}

      .eyebrow {{
        margin: 0 0 10px;
        color: var(--accent);
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }}

      h1 {{
        margin: 0;
        font-family: "IBM Plex Mono", "Cascadia Code", monospace;
        font-size: clamp(2rem, 5vw, 3.4rem);
        line-height: 1.02;
      }}

      .subhead {{
        margin: 14px 0 0;
        max-width: 54rem;
        color: var(--muted);
        font-size: 1rem;
        line-height: 1.6;
      }}

      .meta {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 20px;
      }}

      .pill {{
        border: 1px solid var(--line);
        border-radius: 999px;
        background: #fff;
        padding: 8px 12px;
        font-size: 0.95rem;
      }}

      .cards {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-top: 24px;
      }}

      .card {{
        border-radius: 20px;
        padding: 18px;
        border: 1px solid var(--line);
        background: var(--panel);
        box-shadow: var(--shadow);
      }}

      .card.present {{
        border-color: #9ccfbe;
        background: linear-gradient(180deg, #f7fffb 0%, var(--accent-soft) 100%);
      }}

      .card.missing {{
        border-color: #e3b3b5;
        background: linear-gradient(180deg, #fff8f8 0%, var(--warn-soft) 100%);
      }}

      .card h2 {{
        margin: 0 0 12px;
        font-size: 0.95rem;
        letter-spacing: 0.04em;
      }}

      code {{
        display: block;
        padding: 12px 14px;
        border-radius: 14px;
        background: rgba(255, 255, 255, 0.8);
        border: 1px solid rgba(31, 26, 23, 0.08);
        font-family: "IBM Plex Mono", "Cascadia Code", monospace;
        font-size: 0.95rem;
        overflow-wrap: anywhere;
      }}

      section {{
        margin-top: 24px;
        background: rgba(255, 250, 241, 0.9);
        border: 1px solid rgba(217, 207, 197, 0.85);
        border-radius: 24px;
        box-shadow: var(--shadow);
        padding: 24px;
      }}

      section h2 {{
        margin-top: 0;
        font-size: 1.1rem;
      }}

      table {{
        width: 100%;
        border-collapse: collapse;
      }}

      th, td {{
        text-align: left;
        padding: 10px 12px;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
      }}

      th {{
        width: 34%;
        color: var(--muted);
        font-weight: 600;
      }}

      .hint {{
        margin-top: 16px;
        color: var(--muted);
        font-size: 0.95rem;
      }}

      a {{
        color: var(--accent);
      }}
    </style>
  </head>
  <body>
    <main>
      <header class="hero">
        <p class="eyebrow">fingerprint-proxy local docker demo</p>
        <h1>Forwarded fingerprints are visible at the backend.</h1>
        <p class="subhead">
          This page is rendered by the demo backend behind <code>fingerprint-proxy</code>.
          The values below are the headers the proxy injected into the upstream request.
        </p>
        <div class="meta">
          <div class="pill">Method: <strong>{escape(snapshot["method"])}</strong></div>
          <div class="pill">Path: <strong>{escape(snapshot["path"])}</strong></div>
          <div class="pill">Client: <strong>{escape(snapshot["client_address"])}</strong></div>
        </div>
      </header>

      <section>
        <h2>Detected Fingerprints</h2>
        <div class="cards">{render_fingerprint_cards(snapshot)}</div>
        <p class="hint">
          For raw machine-readable output, request <a href="/json">/json</a>.
        </p>
      </section>

      <section>
        <h2>Forwarded Request Headers</h2>
        <table>
          <tbody>{render_header_rows(snapshot["headers"])}</tbody>
        </table>
      </section>
    </main>
  </body>
</html>
"""


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "fingerprint-proxy-demo-backend/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        snapshot = request_snapshot(self)

        if self.path == "/json":
            payload = json.dumps(snapshot, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if self.path != "/":
            payload = json.dumps(
                {
                    "error": "not_found",
                    "available_paths": ["/", "/json"],
                },
                indent=2,
            ).encode("utf-8")
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        body = render_html(snapshot).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    HTTPServer((LISTEN_HOST, LISTEN_PORT), DemoHandler).serve_forever()
