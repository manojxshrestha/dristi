# Browser Testing with Playwright

Dristi uses Playwright MCP for browser-based testing. All `playwright_browser_*` tools are available to every agent regardless of `bash: deny` — they are MCP tools, not bash commands.

## Available Tools

| Tool | Purpose |
|------|---------|
| `playwright_browser_navigate(url)` | Load a page (lazy-launches browser on first call) |
| `playwright_browser_snapshot()` | Get accessibility tree (use instead of screenshot for analysis) |
| `playwright_browser_take_screenshot(type)` | Capture visual evidence (`png` or `jpeg`) |
| `playwright_browser_evaluate(function)` | Run JS in page context, return result |
| `playwright_browser_fill_form(fields)` | Fill multiple form fields at once |
| `playwright_browser_type(target, text)` | Type into a specific element |
| `playwright_browser_click(target)` | Click an element |
| `playwright_browser_press_key(key)` | Press a keyboard key |
| `playwright_browser_select_option(target, values)` | Select dropdown option |
| `playwright_browser_console_messages(level)` | Get browser console output (error/warning/info/debug) |
| `playwright_browser_network_requests(static)` | Get network requests (filter static=false for API calls) |
| `playwright_browser_handle_dialog(accept)` | Handle alert/confirm/prompt |
| `playwright_browser_tabs(action)` | Manage tabs (list/new/close/select) |
| `playwright_browser_drag(start, end)` | Drag and drop |

## When to Use the Browser (by Vulnerability Class)

| Vulnerability Class | Why Browser Is Required |
|---------------------|------------------------|
| **OAuth / SSO** | OAuth redirect flow is browser-only. `navigate` → `snapshot` to capture `redirect_uri`, `state`, `code` from address bar. `network_requests` to capture token exchange. |
| **DOM-based XSS** | Payload execution only visible in browser DOM. `evaluate` to confirm JS execution. `console_messages` to catch `alert()` proof. |
| **DOM Clobbering / SPA** | Angular/EmberJS/React routes are client-side. `navigate` → `evaluate` to enumerate JS context. |
| **Clickjacking** | PoC requires rendering target in iframe. `navigate` to attacker page → `screenshot` to prove overlay. |
| **CSRF** | PoC form must auto-submit in browser. `navigate` to crafted HTML → verify state change. |
| **WebSocket (CSWSH)** | `WebSocket` constructor only exists in browser JS. `evaluate("new WebSocket(url)")` to test cross-origin. |
| **Open Redirect** | URL parser behavior differs in browser vs curl. `evaluate("window.location.href")` to confirm redirect destination. |
| **Cache Poisoning / Deception** | Authenticated browser session needed to verify cached page serves private data. `navigate` → `network_requests`. |
| **SAML / SSO** | SAML assertions flow through browser redirects. Need `navigate` → `snapshot` to capture `SAMLResponse`. |
| **Host Header** | Password reset link must be clicked in browser to verify poisoning. `navigate` with crafted Host. |
| **File Upload** | Uploaded SVG/HTML must render in browser to verify XSS fires. `navigate` to uploaded file. |
| **Session Testing** | Cookie behavior (secure, httpOnly, SameSite) only testable via real browser interaction. |
| **Evidence / Screenshots** | Every finding needs a visual PoC. `take_screenshot` with visible URL bar. |
| **Authentication** | Login flow (Google OAuth, email+password) requires browser form fill. `navigate` → `fill_form` → `click`. |
| **Prototype Pollution** | Client-side PP only exploitable in browser JS context. `evaluate` to test `__proto__` injection. |
| **CSP Bypass** | CSP enforcement only happens in browser. `console_messages('warning')` to catch CSP violations. |

## Standard Workflow for Browser-Based Testing

```python
# 1. Navigate to target
playwright_browser_navigate(url="https://target.com/path")

# 2. If auth needed
playwright_browser_fill_form(fields=[
    {"target": "#email", "name": "email", "type": "textbox", "value": "user@example.com"},
    {"target": "#password", "name": "password", "type": "textbox", "value": "password123"}
])
playwright_browser_click(target="#login-button")
playwright_browser_snapshot()

# 3. Interact
playwright_browser_click(target="#some-button")
playwright_browser_snapshot()

# 4. Check console for errors/CSP violations
playwright_browser_console_messages(level="warning")

# 5. Check network for API calls
playwright_browser_network_requests(static=False)

# 6. Execute JS in page context
playwright_browser_evaluate(
    function="() => { return window.location.href; }"
)

# 7. Screenshot for evidence
playwright_browser_take_screenshot(
    type="png",
    filename="engagements/recon/domain/finding-name/screenshot.png"
)
```

## Browser Hygiene

1. **Always pass `filename`** to `playwright_browser_take_screenshot()` — omitting it saves to repo root.
2. **Close the browser** after each test session: no explicit close needed — next navigate reuses the page.
3. **One page per domain** — reuse across all tests for that domain.
4. **Use `playwright_browser_snapshot()` for analysis** instead of screenshot — it's text-based and faster.
5. **Use `playwright_browser_network_requests()` for API mapping** instead of crawling every page.
6. **Browser routes through Burp proxy** automatically — requests appear in Burp proxy history.
