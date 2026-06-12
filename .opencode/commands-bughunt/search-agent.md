---
name: search-agent
description: RAG-powered re-dispatch for uncovered vulnerability classes
---

# /search-agent

Search past reports, CVEs, and technique references for vulnerability classes that weren't covered.

## What This Does

1. Checks which hunt agents have not been dispatched
2. Retrieves relevant payloads and bypass techniques
3. Analyzes the target tech stack for missed classes
4. Creates a focused testing task list

## Usage

```
/search-agent
```

## When To Run

After `/deep-think` identifies coverage gaps. Optional skip if all classes were covered.
