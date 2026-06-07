<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/timing-attacks-fundamentals.md -->
# James Kettle Research - Making Timing Attacks Feasible

Direct notes from James Kettle's research (PortSwigger / Black Hat talk: "Listen to the Whispers: Web Timing Attacks That Actually Work").

## Core equation
```
success = signal / noise
```

## Amplify the signal
- Longest split code path  
- Think DoS

Example payloads to force long/expensive paths:
```
GET / HTTP/1.1
X-U: a
X-U: a
… (repeated)
```
With annotation: **{255}** ← repeat the `X-U: a` header 255 times

Alternative single-header amplification:
```
GET / HTTP/1.1
X-U256: a
```
→ **256 times easier to detect**

## Minimize noise
- Embrace performance code features  
- Shortest shared code path

Example noisy headers to remove:
```
GET / HTTP/1.1
Cookie: sid=d83a          ← Remove
DNT: 1                    ← Remove
```
(Burp Repeater-style: **Add** button, **Remove** button next to headers)

These techniques make timing differences detectable even with network/server jitter — focus on maximizing delta (signal) while stabilizing baseline (noise).

## Exclusions (What's NOT in this section)
- No Discovery Overload table  
- No SQLi / sleep / DUPE  
- No exec= chains / nowaf / BigIP 302s  
- No cache hit/miss annotations  
- No memory notes / incremental param adds
