import os
import re
import requests
from flask import Flask, request, render_template
from flag import FLAG

app = Flask(__name__)

# --- Intentionally insecure SSRF fetcher ---
def fetch_url(url: str) -> tuple[int, str]:
    """
    Intentionally vulnerable URL fetcher:
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
        # Keep output sane for UI
        if len(text) > 5000:
            text = text[:5000] + "\n\n[truncated]"
        return r.status_code, text
    except Exception as e:
        return 500, f"Fetch error: {e}"

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/fetch")
def fetch():
    url = request.form.get("url", "").strip()

    # minimal “input hygiene” but NOT security; still vulnerable by design
    if not url:
        return render_template("result.html", url=url, status=400, body="Missing url")

    # Optional: stop obvious whitespace/newlines that break requests
    url = re.sub(r"\s+", "", url)

    status, body = fetch_url(url)
    return render_template("result.html", url=url, status=status, body=body)

# --- Internal-only flag endpoint ---
@app.get("/internal/flag")
def internal_flag():
    """
    Only allow localhost to read the flag.
    Intended solution: SSRF the server into requesting this endpoint.
    """
    remote = request.remote_addr or ""
    if remote not in ("127.0.0.1", "::1"):
        return "Forbidden: internal endpoint (localhost only)\n", 403
    return FLAG + "\n"

# Bonus: internal metadata-style endpoint to make it feel realistic
@app.get("/internal/health")
def internal_health():
    remote = request.remote_addr or ""
    if remote not in ("127.0.0.1", "::1"):
        return "Forbidden\n", 403
    return "OK\n"

if __name__ == "__main__":
    # Bind to 0.0.0.0 so it behaves like a “real” service on a network
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
