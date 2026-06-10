---
name: waf-bypass-f5
description: Skill for bypassing F5 BIG-IP ASM WAF using XSS encoding, XXE exploitation, directory traversal, and known bypass patterns. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 10
---

# F5 BIG-IP ASM WAF Bypass

## Crown Jewel Targets

- BIG-IP ASM with default security policies
- Applications with relaxed security policy sections
- Endpoints not covered by the security policy

## Attack Surface Signals

- `BigIP` or `BIGipServer` cookie
- `X-WA-Info` header
- Header jumbling (unusual header order)
- "The requested URL was rejected" block message

## Step-by-Step Methodology

1. Confirm F5 BIG-IP presence: check for `BigIP` cookie or `X-WA-Info`
2. Test XSS with standard payloads first
3. Apply encoding and obfuscation techniques
4. Test XXE if XML processing endpoints exist
5. Test directory traversal with encoding
6. Try HPP to split payloads

## Payloads

```html
<!-- XSS -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>

<!-- XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Directory Traversal -->
../../../etc/passwd
..%252f..%252f..%252fetc%252fpasswd
```

## Common Root Causes

- F5 ASM security policies are often not comprehensive
- Default policies miss content-type specific attacks (XXE)
- Encoding bypasses signature-based detection
- HPP exploits parameter handling differences

## Gate 0 Validation

- [ ] Have I confirmed F5 BIG-IP presence?
- [ ] Have I tested XSS with encoding?
- [ ] Have I tested XXE if applicable?
- [ ] Have I tried directory traversal?
