<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/sql-injection-bypass.md -->
# SQLi Discovery - Classic Payloads + WAF Block + Timing Alternate Path

Technique: SQL injection probing on an API endpoint.

**Classic payload test:**
| Payload                                      | Response | Response time |
|----------------------------------------------|----------|---------------|
| GET /api/alert?mic='                         | {}       | 162ms         |
| GET /api/alert?mic='||sleep(5)||'            | {}       | 170ms         |

**Observations:**
- Single-quote payload (`mic='`) → normal response `{}` at 162 ms (baseline)  
- Classic sleep-based time-based blind SQLi (`' || sleep(5) || '`) → same `{}` response at 170 ms (almost no delta)  
- Sleep payload marked **DUPE** (indicating blocked / ineffective / WAF caught)

**Alternate discovery path:**
```
' || sleep(5) || '
```

**Final advice:**
> For sleep-capable bugs, use advanced timing for WAF evasion

**Interpretation:**
- Classic string termination (`'`) tested first → confirms potential SQLi context (no error but response exists)  
- Time-based blind attempt with `sleep(5)` → blocked or normalized (minimal time difference ~8 ms) → marked **DUPE** (likely WAF signature match)  
- Recommendation: When basic sleep is caught, switch to **advanced timing techniques** (heavy parameter repetition, cache timing diffs, split code paths, or non-sleep delays like heavy computation) to evade WAF while still measuring backend delays for blind confirmation
