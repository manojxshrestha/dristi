<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/incremental-addition.md -->
# exec= Mass Repetition & Incremental Addition Technique

Screenshot from a Burp Repeater tab during aggressive parameter flooding / bypass testing.

**Massive request (partial - hundreds of repetitions):**
```
exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&exec=1&...
```

**Response:**
```
HTTP/1.0 302 Moved Temporarily
Location: https://redacted.com/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0
```

**Key note from the tab:**
```
then ree add two params or four
then send again send
```

**Interpretation:**
- Flood with extremely high repetition of a single suspicious parameter (`exec=1` repeated hundreds of times) → triggers 302 redirect to **https**
- After initial flood succeeds in changing behavior → **incrementally add 2 or 4 more parameters** and re-send
- Repeat the process to probe for:
  - Gradual escalation of behavior change
  - Different redirect targets
  - Parser overflow / crash
  - WAF bypass via incremental complexity
  - Leaking internal logic (e.g., when/why Location switches schemes)

This is a classic **parameter count amplification + incremental fuzzing** workflow — very effective against:
- BigIP / F5 iRules that normalize or redirect based on param count
- Custom parsers that break at high repetition
- Length-limited filters that allow incremental addition but choke on massive single sends
