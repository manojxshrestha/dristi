# WSTG Business Logic (BUSL)

10 tests for business logic flaws: data validation, request forging, timing attacks, workflow circumvention, file upload, and payment manipulation.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| BUSL-01 | Test Business Logic Data Validation | Bypassing business rules via parameter manipulation |
| BUSL-02 | Test Ability to Forge Requests | Replaying, modifying transaction requests |
| BUSL-03 | Test Integrity Checks | Missing integrity checks on critical operations |
| BUSL-04 | Test for Process Timing | Race conditions in concurrent operations |
| BUSL-05 | Test Number of Times a Function Can Be Used | Coupon reuse, free trial extension, rate limit bypass |
| BUSL-06 | Testing for the Circumvention of Work Flows | Skipping steps in multi-step processes |
| BUSL-07 | Test Defenses Against Application Misuse | Automated abuse, scraping, spamming |
| BUSL-08 | Test Upload of Unexpected File Types | Executable upload via extension manipulation |
| BUSL-09 | Test Upload of Malicious Files | Shell upload, SVG XSS, polyglot files |
| BUSL-10 | Test Payment Functionality | Price manipulation, currency bypass, negative amounts |

## Workflow

1. `get_wstg_test("WSTG-BUSL-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, `burp_intruder`, `burp_scanner`
3. `track_test("WSTG-BUSL-NN")` — record coverage
4. `log_finding()` — if business logic flaw found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Race condition: get_technique_guide("RACE") — send parallel requests, turbolntruder
- Mass assignment: tamper with unexpected parameters
- Coupon/price manipulation: replay, negative values, overflow

## Related PortSwigger Guides

- business-logic.md
- race-conditions.md
- file-upload.md

## Burp Tools

- repeater.send, intruder, proxy.history, sequencer

## Key Checks

- Modify price/quantity in POST body before sending to payment
- Reuse coupon code multiple times
- Skip checkout steps by directly calling confirmation endpoint
- Upload .php, .jsp, .war with Content-Type image/jpeg
- Race condition on limited-use operations
- Negative values in numeric fields

## Reference
- Business logic: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/business-logic-vulnerabilities.md
- Race conditions: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/race-conditions.md
- File upload: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/file-upload-vulnerabilities.md
- Query API: ?ask=<question>
