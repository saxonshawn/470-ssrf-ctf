import os
import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flag import FLAG

app = Flask(__name__)

# IMPORTANT for Render/any reverse proxy:
# Makes Flask respect X-Forwarded-For / X-Forwarded-Proto headers
# so we can correctly distinguish external clients vs localhost.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# --- Intentionally insecure SSRF fetcher ---
def fetch_url(url: str) -> tuple[int, str]:
    """
    Intentionally vulnerable URL fetcher (by design for SSRF CTF):
    - No allowlist
    - No IP restrictions
    - Follows redirects
    - Returns response body (truncated)
    """
    try:
        r = requests.get(
            url,
            timeout=4,
            allow_redirects=True,
            headers={"User-Agent": "A10-SSRF-CTF/1.0"},
        )
        text = r.text
        if len(text) > 5000:
            text = text[:5000] + "\n\n[truncated]"
        return r.status_code, text
    except Exception as e:
        return 500, f"Fetch error: {e}"

def client_ip() -> str:
    """
    After ProxyFix, request.access_route will contain the real client IP first
    (based on X-Forwarded-For). Fallback to remote_addr.
    """
    if request.access_route:
        return request.access_route[0]
    return request.remote_addr or ""

def is_local_request() -> bool:
    """
    True only when the request really originates from localhost.
    """
    ip = client_ip()
    return ip in ("127.0.0.1", "::1")

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/fetch")
def fetch():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("result.html", url=url, status=400, body="Missing url")

    # Remove whitespace that can break requests
    url = re.sub(r"\s+", "", url)

    # Hosting-friendly: allow relative SSRF targets like /internal/flag
    # This makes the intended solve easy on Render (no port guessing).
    if url.startswith("/"):
        url = f"http://127.0.0.1{url}"

    # Optional: prevent weird schemes from confusing requests (still SSRF)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return render_template("result.html", url=url, status=400, body="Only http/https allowed")

    status, body = fetch_url(url)
    return render_template("result.html", url=url, status=status, body=body)

# --- Internal-only endpoints ---
@app.get("/internal/flag")
def internal_flag():
    """
    Only allow true localhost to read the flag.
    Intended solution: SSRF the server into requesting this endpoint.
    """
    if not is_local_request():
        return "Forbidden: internal endpoint (localhost only)\n", 403
    return FLAG + "\n"

@app.get("/internal/health")
def internal_health():
    if not is_local_request():
        return "Forbidden\n", 403
    return "OK\n"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
