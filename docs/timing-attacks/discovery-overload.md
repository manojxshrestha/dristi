<!-- Mirrored from manojxshrestha/playbook/docs/web-timing-attacks/discovery-overload.md -->
# Discovery Overload - Probing for Hidden Parameters

Goal: Send weird / unexpected single parameters (headers or query params) and observe differences in:
- HTTP response code  
- Connection behavior  
- Response time (large deltas indicate different code paths / processing)  

| Payload                        | Response                        | Response time |
|--------------------------------|---------------------------------|---------------|
| foo: x                         | HTTP/1.1 200 OK                 | 50ms          |
| commonconfig: x                | HTTP/1.1 200 OK                 | 55ms          |
| commonconfig: {}               | HTTP/1.1 200 OK                 | 50ms          |
| foo: x                         | --connection closed--           | 30ms          |
| authorization: x               | --connection closed--           | 50ms          |
| GET /?id=random                | HTTP/1.1 200 OK                 | 310ms         |
| GET /?Fooo=random              | HTTP/1.1 200 OK                 | 22ms          |
| GET /?foo=random               | HTTP/1.1 200 OK                 | 22ms          |

Key observations:
- Baseline normal-looking params (`foo: x`, `commonconfig: x`, `commonconfig: {}`) → ~50-55 ms, 200 OK  
- Suspicious / module-triggering headers (`authorization: x`) → connection closed early  
- Query parameter with random value on known key (`?id=random`) → significantly slower (310 ms) → likely cache miss / DB hit / expensive path  
- Made-up or case-variant params (`?Fooo=random`, `?foo=random`) → very fast (22 ms) → probably skipped / not processed / cache hit  

This pattern is used to fingerprint:
- Which parameters are actually parsed / trigger different code paths  
- Which ones might be interesting for further fuzzing (e.g. `exec`, `commonconfig`, `id`)  
- Cache key behavior (slow = probably hashed/used in key, fast = ignored)

Very effective for discovering hidden/debug/backdoor-like parameters in custom or legacy apps.
