# Browser Flow — Playwright for Client-Side Testing

Dristi uses Playwright MCP for browser-based testing. This covers authentication, session management, client-side validation, and DOM-based bug hunting.

## Available Tools

| Tool | Purpose |
|---|---|
| `playwright_browser_navigate(url)` | Load a page |
| `playwright_browser_snapshot()` | Get accessibility tree (use instead of screenshot for analysis) |
| `playwright_browser_take_screenshot(type)` | Capture visual evidence |
| `playwright_browser_evaluate(function)` | Run JS in page context |
| `playwright_browser_fill_form(fields)` | Fill multiple form fields at once |
| `playwright_browser_type(target, text)` | Type into an element |
| `playwright_browser_click(target)` | Click an element |
| `playwright_browser_press_key(key)` | Press keyboard key |
| `playwright_browser_select_option(target, values)` | Select dropdown option |
| `playwright_browser_console_messages(level)` | Get browser console output |
| `playwright_browser_network_requests(static)` | Get network requests |
| `playwright_browser_handle_dialog(accept)` | Handle alert/confirm/prompt |
| `playwright_browser_tabs(action)` | Manage tabs |

## Auth Session Management

### Method 1: Login form (preferred when possible)

Navigate to login page, fill credentials, submit — the browser maintains cookies automatically:

```js
await page.goto('https://target.com/login');
await page.fill('input[name="email"]', 'test@test.com');
await page.fill('input[name="password"]', 'Test123!');
await page.click('button[type="submit"]');
await page.waitForNavigation();
```

After login, all subsequent `navigate()` calls maintain the session. Capture cookies for curl/Burp:

```js
const cookies = await page.context().cookies();
const token = await page.evaluate(() => localStorage.getItem('token'));
```

### Method 2: Set cookies directly

If you have an existing session cookie from Burp/curl:

```js
await page.context().addCookies([{
  name: 'session',
  value: '<session_cookie_value>',
  domain: '.target.com',
  path: '/'
}]);
await page.goto('https://target.com/authenticated-page');
```

### Method 3: Set localStorage tokens

For SPAs that store JWT in localStorage:

```js
await page.goto('https://target.com');
await page.evaluate(() => {
  localStorage.setItem('token', '<jwt_token>');
  localStorage.setItem('user', JSON.stringify({id: 1, role: 'admin'}));
});
await page.goto('https://target.com/dashboard');
```

### Method 4: Auth header injection

For APIs and SPAs using Bearer tokens:

```js
await page.route('**/api/**', route => {
  const headers = route.request().headers();
  headers['Authorization'] = 'Bearer <token>';
  route.continue({headers});
});
await page.goto('https://target.com/app');
```

## Per-Phase Browser Workflow

### P2: AUTH — Browser-Based Login

- Navigate to the app to see the login/signup flow
- Fill and submit the registration form to create a test account
- After login, extract cookies and tokens for curl/Burp: `page.context().cookies()`, `localStorage`
- Take a screenshot of the authenticated dashboard as proof of session
- Store cookies for reuse across phases

### P4: RECON — Map Client-Side Surface

- Navigate through the app to let it generate traffic through Burp Proxy
- Open multiple tabs to map different sections
- Use `playwright_browser_console_messages('error')` to catch JS errors (potential info leaks)
- Use `playwright_browser_network_requests(true)` to discover API calls
- Use `playwright_browser_snapshot()` to get the full accessibility tree of each page

### P5: SURFACE — Interactive Probing

- Navigate to endpoints identified in recon
- Use `playwright_browser_evaluate()` to inspect DOM state:
  - `() => document.cookie` — check cookie flags (HttpOnly, Secure, SameSite)
  - `() => JSON.stringify(window.__INITIAL_STATE__)` — check for data leaks in page state
  - `() => document.querySelectorAll('script').length` — check for inline scripts
- Fill forms and submit to discover hidden parameters
- Take snapshots for each distinct endpoint type

### P6: HUNT — Vulnerability Validation

#### Open Redirect

```js
await page.goto('https://target.com/redirect?url=https://evil.com');
await page.waitForTimeout(1000);
// Check if current URL changed to evil.com
const currentUrl = await page.evaluate(() => window.location.href);
```

#### DOM XSS

```js
await page.goto('https://target.com/search?q=<img+src=x+onerror=alert(1)>');
await page.waitForTimeout(1000);
const consoleErrors = await page.context().pages()[0].evaluate(() => {
  // Check if the payload rendered in the DOM
  return document.body.innerHTML.includes('<img src=');
});
```

#### PostMessage Capture — Multi-Tab Test

Listen on the target page, then trigger from a second tab:

```js
// Tab 1: Navigate to target page and start listening
await page.goto('https://target.com/vulnerable-page');
await page.evaluate(() => {
  window.addEventListener('message', (e) => {
    console.log('[POSTMESSAGE]', JSON.stringify({origin: e.origin, data: e.data}));
  });
});

// Tab 2: Open a new tab that sends postMessage to the opener
const tab2 = await context.newPage();
await tab2.goto('https://attacker.com/exploit.html');
// The exploit page does: window.opener.postMessage({...}, '*');
// Tab 1's listener captures it via console messages

// Check captured messages
const msgs = await page.context().pages()[0].evaluate(() => {
  // Read from a window-level array if listener stored them
  return window.__postMessages || [];
});
```

If the target uses `window.postMessage` for cross-origin communication (OAuth popups, third-party widgets, payment iframes), test:
1. **Origin validation bypass** — send `{...}` from `https://evil.com` — does the target accept it?
2. **Data structure injection** — send unexpected data types (string instead of object, array instead of string)
3. **Prototype pollution via postMessage** — send `{__proto__: {isAdmin: true}}`
4. **XSS via postMessage** — if target reads `event.data.html` and sets `innerHTML`
5. **Credential leakage** — check if target sends tokens/cookies back via postMessage response

```js
// Test: send malicious postMessage as if from an allowed origin
await page.evaluate(() => {
  window.postMessage({type: 'renderHtml', html: '<img src=x onerror=alert(1)>'}, '*');
});
// Check console for errors and snapshot for injected content
```

#### CSP / Client-Side Security

```js
await page.goto('https://target.com');
const csp = (await page.evaluate(() => {
  const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  return meta ? meta.content : 'No meta CSP';
}));
// Check for script-src 'unsafe-inline', missing object-src, etc.
```

#### localStorage / sessionStorage Inspection

```js
const storage = await page.evaluate(() => ({
  localStorage: { ...localStorage },
  sessionStorage: { ...sessionStorage }
}));
```

### P10: CAPTURE — Evidence Collection

- `playwright_browser_take_screenshot('png')` — full-page or viewport screenshot
- `playwright_browser_snapshot()` — accessibility tree for DOM-based bugs
- `playwright_browser_console_messages('error')` — capture error output
- `playwright_browser_network_requests(false)` — capture request/response pairs

## Browser + Burp Integration

Browser → Burp Proxy → Target

1. Configure Burp Proxy on port 8080
2. Launch Playwright with proxy:
```js
const browser = await chromium.launch({
  proxy: { server: 'http://127.0.0.1:8080' }
});
```
3. Browse the target through Playwright — Burp captures all traffic
4. Check `burp_get_proxy_http_history()` to review captured requests
5. Send interesting requests to Repeater/Intruder from Burp

## Common Browser Testing Patterns

### Check if page loads without errors
```js
const errors = await page.evaluate(() => {
  return window.__ERRORS__ || [];
});
```

### Intercept and modify responses
```js
await page.route('**/api/users/**', route => {
  const response = route.response();
  // Modify response on the fly
  route.fulfill({
    body: JSON.stringify({role: 'admin', ...}),
    headers: response.headers()
  });
});
```

### Detect open redirect without navigation
```js
await page.route('**/*', route => {
  const url = route.request().url();
  if (url.includes('evil.com') || url.includes('attacker')) {
    console.log('[REDIRECT DETECTED]', url);
  }
  route.continue();
});
```

## Performance Tips

- Use `playwright_browser_snapshot()` for DOM analysis instead of screenshot — it's text-based and faster
- Use `playwright_browser_network_requests()` for API mapping instead of crawling every page
- Use `playwright_browser_console_messages('warning')` to catch `SAMEORIGIN` / CSP violations without parsing headers
- One browser page per domain — reuse across all tests for that domain
