# OWASP WSTG Knowledge Base

This directory contains pentest instructions based on the OWASP Web Security Testing Guide (WSTG) v4.2. Full coverage: **109 test cases** across all 12 categories.

## Categories

| # | Code | Category | Tests |
|---|------|----------|-------|
| 01 | INFO | Information Gathering | 10 |
| 02 | CONF | Configuration and Deployment Management | 14 |
| 03 | IDNT | Identity Management | 5 |
| 04 | ATHN | Authentication | 11 |
| 05 | ATHZ | Authorization | 5 |
| 06 | SESS | Session Management | 11 |
| 07 | INPV | Input Validation | 20 |
| 08 | ERRH | Error Handling | 2 |
| 09 | CRYP | Cryptography | 4 |
| 10 | BUSL | Business Logic | 10 |
| 11 | CLNT | Client-Side | 14 |
| 12 | APIT | API Testing | 3 |

**Total: 109 tests**

## Adding New Tests

1. Create a markdown file in the appropriate category directory
2. Name it `WSTG-<CODE>-<NUMBER>.md` (e.g., `WSTG-INPV-03.md`)
3. Include YAML frontmatter with `id`, `title`, `category`, `severity_range`
4. Follow the standard sections: Summary, Test Objectives, Prerequisites, Test Steps (with CLI Actions), Payloads, Detection Criteria, Severity Assessment, Remediation, References
