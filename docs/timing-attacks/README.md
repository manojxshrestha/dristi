<!-- Mirrored from https://github.com/manojxshrestha/playbook/tree/main/docs/web-timing-attacks -->
# Web Timing Attacks & Parameter Discovery

A comprehensive guide to practical timing attacks, hidden parameter discovery, and WAF bypass techniques based on James Kettle's research (PortSwigger / Black Hat talk: "Listen to the Whispers: Web Timing Attacks That Actually Work").

## Table of Contents

### Fundamentals
1. [Timing Attack Fundamentals](timing-attacks-fundamentals.md) - Core equation, signal amplification, and noise minimization

### Discovery Techniques
2. [Discovery Overload - Probing for Hidden Parameters](discovery-overload.md) - Finding hidden parameters
3. [Discovery Overload - Cache Key Detection](cache-key-detection.md) - Identifying cache-included parameters

### Practical Testing
4. [Encoded Payload Testing](encoded-payload-testing.md) - WAF bypass with encoding
5. [Parameter Repetition Testing](parameter-repetition.md) - Mass parameter techniques
6. [Incremental Addition Technique](incremental-addition.md) - Iterative fuzzing approach
7. [Proving Concept at Scale](proving-concept-scale.md) - Large-scale testing

### Advanced Techniques
8. [SQL Injection Timing Bypass](sql-injection-bypass.md) - Evading WAF with timing

### Workflows
9. [Burp Suite Workflow](burp-workflow.md) - Practical examples and reference

## Core Equation

```
success = signal / noise
```

## Techniques Overview

| Technique | Purpose |
|-----------|---------|
| Header Amplification (255x) | Force expensive code paths |
| X-U256 | 256x easier to detect |
| Discovery Overload | Find hidden parameters |
| Cache Key Detection | Identify cached params |
| Parameter Pollution | Trigger different behavior |
| Incremental Fuzzing | Bypass length limits |
| Encoding Bypass | Evade WAF signatures |
| Advanced Timing | SQLi WAF evasion |

## References

- James Kettle, PortSwigger: "Listen to the Whispers: Web Timing Attacks That Actually Work" (Black Hat talk)
- PortSwigger Web Security Blog
- F5 BigIP iRules documentation

## License

MIT License - Use for educational purposes only. Always obtain proper authorization before testing on systems you don't own.
