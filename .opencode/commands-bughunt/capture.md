---
name: capture
description: Evidence collection — HTTP requests, screenshots, collaborator, PII redaction
---

# /capture

Collect all evidence needed before report submission.

## What This Does

1. Captures HTTP request/response pairs
2. Takes browser screenshots of demonstrated impact
3. Checks Burp Collaborator for OOB interactions
4. Redacts cookies, tokens, and PII from evidence
5. Packages evidence for the report

## Usage

```
/capture
```

## When To Run

Before `/report`. All findings should be validated first.
