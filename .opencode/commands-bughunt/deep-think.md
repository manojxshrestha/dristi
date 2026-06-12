---
name: deep-think
description: First-principles gap analysis — find what automation misses
---

# /deep-think

Step back and think. After automated hunting, identify attack paths the tools missed.

## What This Does

1. Reviews all findings and attack surface
2. Identifies gaps in coverage (business logic, chaining, edge cases)
3. Brainstorms novel attack chains
4. Returns gap analysis with suggested next tests

## Usage

```
/deep-think
```

## When To Run

After `/hunt` completes or stalls. Optional — skip if all high-value paths were covered.
