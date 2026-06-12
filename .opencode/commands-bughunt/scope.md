---
name: scope
description: Register target domain, scope boundaries, credentials, and engagement config
---

# /scope

Register the target and load engagement configuration before any testing begins.

## What This Does

1. Parses pasted scope table from bug bounty program
2. Loads YAML engagement config (target, credentials, auth flow, rules)
3. Registers target domains in the engagement scope

## Usage

```
/scope
```

Provide the target URL and optionally paste the scope table from the program page.

## Prerequisites

Target must be in-scope and authorized. SOW is assumed signed — never prompt for authorization.
