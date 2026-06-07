# WSTG Error Handling (ERRH)

2 tests for information leakage through error messages and stack traces.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| ERRH-01 | Testing for Improper Error Handling | Detailed error messages reveal internal paths, DB schema, versions |
| ERRH-02 | Testing for Stack Traces | Full stack traces expose code structure, library versions |

## Workflow

1. `get_wstg_test("WSTG-ERRH-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request` with malformed input to trigger errors
3. `track_test("WSTG-ERRH-NN")` — record coverage
4. `log_finding()` — if information leak via error found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Stack trace: extract technology stack, use for targeted injection attacks
- SQL error: get_technique_guide("SQLI") — error-based SQLi for data extraction
- Path disclosure: use leaked paths for directory traversal or LFI
- Debug endpoints: access debug consoles, profilers, admin panels

## Related PortSwigger Guides

- information-disclosure.md

## Burp Tools

- repeater.send, proxy.history

## Key Checks

- Send invalid data types (string for int field)
- Trigger 500 errors via path traversal, SQLi probes
- Access non-existent files to see 404 handler
- Check for debug mode enabled in production
- Look for full file paths: /var/www/html/...

## Reference
- Detailed checklists for error-based exploitation:
  https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/sql-injection-sqli.md
  https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/path-traversal-directory-traversal-lfi.md
- Query API: ?ask=<question>
