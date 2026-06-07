# WSTG Client-Side (CLNT)

14 tests for DOM-based XSS, clickjacking, CORS, WebSockets, web messaging, browser storage, prototype pollution, and third-party inclusion.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| CLNT-01 | Testing for DOM-Based Cross-Site Scripting | Client-side XSS via DOM sinks |
| CLNT-02 | Testing for JavaScript Execution | eval(), setTimeout with user input |
| CLNT-03 | Testing for HTML Injection | innerHTML, document.write with unsanitized input |
| CLNT-04 | Testing for Client-side URL Redirect | open redirect via location.hash, query params |
| CLNT-05 | Testing for CSS Injection | CSS selectors exfiltrate data |
| CLNT-06 | Testing for Client-side Resource Manipulation | Prototype override via JSON.parse |
| CLNT-07 | Testing Cross Origin Resource Sharing | Wildcard origin, credential reflection |
| CLNT-08 | Testing for Clickjacking | Missing X-Frame-Options, CSP frame-ancestors |
| CLNT-09 | Testing WebSockets | Unencrypted WebSocket, missing origin check |
| CLNT-10 | Testing Web Messaging | postMessage origin validation bypass |
| CLNT-11 | Testing Browser Storage | Sensitive data in localStorage, sessionStorage |
| CLNT-12 | Testing for Inclusion of Third-Party Functionality | Malicious CDN script, subresource integrity missing |
| CLNT-13 | Testing for Reverse Tabnabbing | target=_blank without rel=noopener |
| CLNT-14 | Testing for Client-side Prototype Pollution | Object prototype pollution via merge/clone |

## Workflow

1. `get_wstg_test("WSTG-CLNT-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, `burp_proxy_history`, browser testing
3. `track_test("WSTG-CLNT-NN")` — record coverage
4. `log_finding()` — if client-side vuln found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- DOM XSS: get_technique_guide("XSS") — sink context html_body, html_attribute, javascript_string
- CSRF: get_technique_guide("CSRF") — generate PoC HTML form, test lack of tokens
- Clickjacking: get_technique_guide("CLICK") — iframe PoC page, test X-Frame-Options
- CORS: get_technique_guide("CORS") — origin reflection, preflight bypass
- WebSockets: get_technique_guide("WS") — CSWSH, message injection

## Related PortSwigger Guides

- dom-based.md, cross-site-scripting.md, cors.md, clickjacking.md
- websockets.md, prototype-pollution.md, web-messaging.md

## Burp Tools

- repeater.send, proxy.history, scanner

## Key Checks

- postMessage without origin check
- CORS with Access-Control-Allow-Origin: *
- localStorage containing tokens or PII
- Missing SRI on third-party scripts
- window.open with user-controlled URL
- Object merge functions without prototype checks

## Reference
- XSS: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/xss-cross-site-scripting.md
- CSRF: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/csrf-cross-site-request-forgery.md
- Clickjacking: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/clickjacking.md
- CORS: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/cors-cross-origin-resource-sharing-misconfiguration.md
- Web cache deception: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/web-cache-deception.md
- Prototype pollution: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/prototype-pollution.md
- Query API: ?ask=<question>
