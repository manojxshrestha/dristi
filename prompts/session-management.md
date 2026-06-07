# WSTG Session Management (SESS)

11 tests for session handling, cookie attributes, CSRF, JWT, session fixation, timeout, and hijacking.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| SESS-01 | Testing for Session Management Schema | Predictable tokens, no entropy in session IDs |
| SESS-02 | Testing for Cookies Attributes | Missing Secure, HttpOnly, SameSite flags |
| SESS-03 | Testing for Session Fixation | Attacker can set victims session ID |
| SESS-04 | Testing for Exposed Session Variables | Session data in URL, logs, referer headers |
| SESS-05 | Testing for Cross Site Request Forgery | Missing CSRF tokens, weak token validation |
| SESS-06 | Testing for Logout Functionality | Session not invalidated on logout |
| SESS-07 | Testing Session Timeout | No idle timeout, excessive session lifespan |
| SESS-08 | Testing for Session Puzzling | Session variable collision, attribute pollution |
| SESS-09 | Testing for Session Hijacking | Session leakage via XSS, MITM, referer |
| SESS-10 | Testing JSON Web Tokens | alg:none, weak secret, missing signature verification |
| SESS-11 | Testing for Session Replay | Old session tokens accepted after logout |

## Workflow

1. `get_wstg_test("WSTG-SESS-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, `burp_scanner`
3. `track_test("WSTG-SESS-NN")` — record coverage
4. `log_finding()` — if session flaw found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Session fixation: get_technique_guide("SESS") — set session cookie before login
- Weak token: get_technique_guide("SESS") — decode, predict, or forge session tokens
- CSRF token bypass: get_technique_guide("CSRF") — token stripping, reuse, weak validation
- Session timeout: get_technique_guide("SESS") — reuse expired tokens after manipulation

## Related PortSwigger Guides

- jwt.md
- csrf.md
- authentication.md

## Burp Tools

- repeater.send, scanner, proxy.history, sequencer (token analysis)

## Key Checks

- Cookie without Secure flag on HTTPS
- JWT alg header accepts none
- CSRF token not tied to session
- Session still valid after logout
- SameSite=Lax allows CSRF via GET

## Reference
- Auth checklist: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/authentication-security-testing.md
- JWT: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/jwt-security-testing.md
- Query API: ?ask=<question>
