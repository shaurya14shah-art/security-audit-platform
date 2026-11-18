from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from typing import Optional

app = FastAPI(
    title="Local Vulnerability Testing Lab",
    version="1.0.0",
    description="Intentionally vulnerable local laboratory for safe cybersecurity research and detection verification.",
)

MOCK_USERS = {
    "101": {"record_id": "101", "name": "Alice Researcher", "role": "lab_analyst", "email": "alice@local.lab"},
    "102": {"record_id": "102", "name": "Bob Executive", "role": "finance_lead", "email": "bob@local.lab"},
    "103": {"record_id": "103", "name": "Admin Root", "role": "system_admin", "email": "admin@local.lab"},
}


@app.get("/", response_class=HTMLResponse)
async def lab_home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Local Vulnerability Testing Lab</title>
        <style>
            body { font-family: monospace; background: #0f172a; color: #38bdf8; padding: 40px; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #0284c7; max-width: 800px; margin: 0 auto; }
            h1 { color: #f43f5e; }
            a { color: #a855f7; }
            li { margin-bottom: 8px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>[SAFE LAB] Local Vulnerability Research Target</h1>
            <p>This service provides safe, non-destructive demonstration endpoints to verify scanner detection modules.</p>
            <h3>Endpoints:</h3>
            <ul>
                <li><a href="/lab/insecure-headers">/lab/insecure-headers</a> - Omitted CSP, HSTS, X-Content-Type-Options</li>
                <li><a href="/lab/cookies">/lab/cookies</a> - Cookies missing HttpOnly, Secure, SameSite</li>
                <li><a href="/lab/cors">/lab/cors</a> - Permissive arbitrary CORS reflection</li>
                <li><a href="/robots.txt">/robots.txt</a> - Disclosed sensitive routes</li>
                <li><a href="/lab/search?q=test">/lab/search?q=test</a> - Unescaped HTML parameter reflection</li>
                <li><a href="/lab/api/user/102/profile">/lab/api/user/102/profile</a> - IDOR simulation</li>
                <li><a href="/lab/admin/metrics">/lab/admin/metrics</a> - Unauthenticated administrative metrics</li>
                <li><a href="/lab/redirect?target=https://example.com">/lab/redirect</a> - Open redirect parameter</li>
            </ul>
        </div>
    </body>
    </html>
    """


@app.get("/lab/insecure-headers", response_class=HTMLResponse)
async def insecure_headers_demo():
    content = "<html><body><h1>Legacy Application Portal</h1><p>Missing security headers demonstration.</p></body></html>"
    headers = {
        "Server": "Apache/2.2.8 (Unix) mod_ssl/2.2.8 OpenSSL/0.9.8e",
        "X-Powered-By": "PHP/5.4.0",
        # Notice CSP, HSTS, X-Frame-Options, X-Content-Type-Options are explicitly omitted
    }
    return Response(content=content, media_type="text/html", headers=headers)


@app.get("/lab/cookies")
async def weak_cookies_demo(response: Response):
    # Set cookies missing defensive attributes
    response.set_cookie(key="lab_session_id", value="sess_mock_token_abc12345", httponly=False, secure=False)
    response.set_cookie(key="tracking_id", value="trk_998877", httponly=False, secure=False)
    return {"message": "Cookies set without HttpOnly or Secure flags"}


@app.get("/lab/cors")
async def cors_demo(request: Request):
    origin = request.headers.get("origin", "*")
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    }
    return JSONResponse(content={"secret_vault_balance": 500000, "access": "granted"}, headers=headers)


@app.get("/robots.txt", response_class=HTMLResponse)
async def robots_txt():
    return """User-agent: *
Disallow: /admin/secret-portal
Disallow: /api/v1/private-backup
Disallow: /internal/db-admin
Disallow: /staging/config
"""


@app.get("/lab/search", response_class=HTMLResponse)
async def search_reflection(q: str = ""):
    # Intentionally reflects query parameter unencoded in HTML
    return f"""
    <html>
    <body>
        <h2>Search Results for: {q}</h2>
        <p>Zero items found for query: {q}</p>
        <form method="POST" action="/lab/contact">
            <input type="text" name="feedback" placeholder="Leave message"/>
            <button type="submit">Submit Feedback (No CSRF Token)</button>
        </form>
    </body>
    </html>
    """


@app.get("/lab/api/user/{user_id}/profile")
async def user_profile(user_id: str):
    # IDOR simulation: returns user record without checking session authorization
    if user_id in MOCK_USERS:
        return MOCK_USERS[user_id]
    return JSONResponse(status_code=404, content={"error": "User record not found"})


@app.get("/lab/admin/metrics")
async def admin_metrics():
    # Unprotected administrative telemetry
    return {
        "system_metrics": {
            "uptime_seconds": 128400,
            "connected_nodes": 4,
            "database_cluster": "lab-pg-primary.internal",
            "active_worker_threads": 16,
            "memory_utilization_mb": 412,
        }
    }


@app.get("/lab/redirect")
async def open_redirect(target: Optional[str] = None):
    if target:
        return RedirectResponse(url=target, status_code=302)
    return {"message": "Provide ?target=https://..."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8888)
