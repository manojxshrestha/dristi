<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/cache-key-detection.md -->
# Discovery Overload - Cache Key & Timing Probing

Goal: Probe individual parameters (headers / query) to detect:
- Different code paths (timing deltas)  
- Connection behavior changes  
- **Cache key inclusion/exclusion** (slow = likely in key → miss on random; fast = not in key → hit)

| Payload                        | Response                        | Response time | Cache Annotation              |
|--------------------------------|---------------------------------|---------------|-------------------------------|
| fooo: x                        | HTTP/1.1 200 OK                 | 50ms          | -                             |
| commonconfig: x                | HTTP/1.1 200 OK                 | 55ms          | -                             |
| commonconfig: {}               | HTTP/1.1 200 OK                 | 50ms          | -                             |
| fooo: x                        | --connection closed--           | 30ms          | -                             |
| authorization: x               | --connection closed--           | 50ms          | -                             |
| GET /?id=random                | HTTP/1.1 200 OK                 | 310ms         | In cache key → Cache miss     |
| GET /?Fooo=random              | HTTP/1.1 200 OK                 | 22ms          | Not in cache key → Cache hit  |
| GET /?Foo=random               | HTTP/1.1 200 OK                 | 22ms          | Not in cache key → Cache hit  |

Interpretation:
- Parameters included in the cache key cause **cache misses** on random/unique values → slower responses (310 ms) due to full backend computation  
- Ignored / non-key parameters → treated as cacheable → fast **cache hits** (~22 ms) even on random values  
- This leaks which params are actually used for caching / uniqueness → high-value targets for further fuzzing (e.g. injection, bypass, DoS)

This pattern (timing + cache behavior delta) is extremely powerful for:
- Fingerprinting internal parameter usage  
- Discovering cache poisoning / deception vectors  
- Identifying candidates for parameter-based attacks (e.g. exec, commonconfig, id)
