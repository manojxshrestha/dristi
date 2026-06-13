---
name: waf-hpp-hpf
description: Skill for bypassing WAFs using HTTP Parameter Pollution (HPP) and HTTP Parameter Fragmentation (HPF) techniques. Exploits differences in how WAFs and backend servers handle multiple parameters with the same name. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 15
---

# WAF HPP & HPF Bypass

## Crown Jewel Targets

- Applications where WAF and backend handle parameters differently
- Java/Tomcat backends (first param wins)
- ASP.NET/IIS backends (concat by comma)
- PHP/Apache backends (last param wins)

## Attack Surface Signals

- WAF inspects each parameter individually (perfect for HPP splitting)
- Application accepts duplicate parameter names
- Error messages reveal parameter handling behavior

## Step-by-Step Methodology

1. Identify the backend technology from response headers
2. Determine how the backend handles duplicate parameters
3. Split attack payload across multiple parameters with the same name
4. The WAF sees individually benign parameters
5. The backend concatenates/reassembles the malicious payload

## HPP Behavior by Backend

| Backend | Behavior | Attack Pattern |
|---------|----------|----------------|
| ASP/IIS | Concatenation by comma | `?a=1&a=2` -> `1,2` |
| ASP.NET/IIS | Concatenation by comma | `?a=1&a=2` -> `1,2` |
| JSP/Tomcat | First parameter wins | `?a=1&a=2` -> `1` |
| PHP/Apache | Last parameter wins | `?a=1&a=2` -> `2` |
| PHP/Zeus | Last parameter wins | `?a=1&a=2` -> `2` |
| Python/Zope | First parameter wins | `?a=1&a=2` -> `1` |
| IceWarp | Array returned | `?a=1&a=2` -> `['1','2']` |
| DBMan | Concatenation by ~~ | `?a=1&a=2` -> `1~~2` |

## Payload Examples

```sql
-- SQLi via HPP (ASP.NET - comma concatenation)
?id=1'&id=UNION&id=SELECT&id=1,2,3--
-- WAF sees: ?id=1', ?id=UNION (benign individually)
-- Backend sees: 1',UNION,SELECT,1,2,3--

-- XSS via HPF
?param1=<script>&param2=alert(1)&param3=</script>
-- If concatenated: <script>alert(1)</script>
```

## Common Root Causes

- WAFs inspect each parameter value independently
- Backend servers reassemble parameters differently than WAF expects
- Parameter handling logic varies significantly between server platforms
- HPP/HPF exploits the parsing discrepancy between WAF and application

## Gate 0 Validation

- [ ] Have I identified the backend technology?
- [ ] Does the backend accept duplicate parameters?
- [ ] Have I determined the concatenation/behavior pattern?
- [ ] Have I successfully split a payload across parameters?
