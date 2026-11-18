import pytest
import httpx
from app.scanners.passive.headers import SecurityHeadersScanner
from app.scanners.passive.cookies import CookieSecurityScanner
from app.scanners.active.cors_analyzer import CORSAnalyzerScanner


@pytest.mark.asyncio
async def test_passive_security_headers_scanner():
    scanner = SecurityHeadersScanner()

    # Mock transport responding without CSP and HSTS
    def mock_handler(request: httpx.Request) -> httpx.Response:
        headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41",
            # No Content-Security-Policy, No HSTS, No X-Frame-Options
        }
        return httpx.Response(200, headers=headers, text="<html><body>Hello</body></html>", request=request)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan("https://test.local", client, {})

    titles = [f.title for f in findings]
    assert any("Missing Content-Security-Policy" in t for t in titles)
    assert any("Missing HTTP Strict-Transport-Security" in t for t in titles)
    assert any("Missing X-Frame-Options" in t for t in titles)


@pytest.mark.asyncio
async def test_cookie_security_scanner():
    scanner = CookieSecurityScanner()

    def mock_handler(request: httpx.Request) -> httpx.Response:
        # Set cookies without HttpOnly and without Secure
        headers = [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "session_token=secret123; Path=/"),
            ("Set-Cookie", "user_prefs=dark; Path=/; SameSite=Lax"),
        ]
        return httpx.Response(200, headers=headers, json={"status": "ok"}, request=request)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan("https://test.local", client, {})

    titles = [f.title for f in findings]
    assert any("Missing 'HttpOnly' Flag" in t for t in titles)
    assert any("Missing 'Secure' Flag" in t for t in titles)


@pytest.mark.asyncio
async def test_active_cors_analyzer():
    scanner = CORSAnalyzerScanner()

    # Mock server that blindly reflects Origin with Credentials
    def mock_handler(request: httpx.Request) -> httpx.Response:
        req_origin = request.headers.get("origin", "")
        headers = {
            "Access-Control-Allow-Origin": req_origin,
            "Access-Control-Allow-Credentials": "true",
        }
        return httpx.Response(200, headers=headers, json={"user_id": 42}, request=request)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await scanner.scan("http://localhost:3000/api/user", client, {})

    assert len(findings) > 0
    assert any("Critical CORS Misconfiguration" in f.title for f in findings)
    assert findings[0].severity == "CRITICAL"
