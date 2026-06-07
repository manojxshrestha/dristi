# Engagement Config Schema

Reference for all fields in the YAML engagement config file.

## mode (optional)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `full` | Testing mode. `full` = standard pentest with all gates enforced. `ctf` = relaxed gates for CTF challenges and small apps (15s gate timing, no QA reviewer required, halved completion thresholds, tool requirements downgraded to warnings). |

## target (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Main target URL. Must start with `http://` or `https://` |
| `scope` | list[string] | No | In-scope domains. Auto-registered via `register_scope()` |
| `exclude` | list[string] | No | Domains explicitly excluded from testing |

## authentication (optional)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `login_type` | string | Yes | One of: `form`, `sso`, `api`, `manual`, `none` |
| `login_url` | string | No | URL of the login page |
| `credentials.username` | string | Conditional | Required for form/sso/api login types |
| `credentials.password` | string | Conditional | Required for form/sso/api login types |
| `sso.provider` | string | No | SSO provider: `keycloak`, `auth0`, `okta`, `azure_ad`, `custom` |
| `sso.auth_domain` | string | No | Domain of the SSO provider |
| `sso.realm` | string | No | Keycloak realm name |
| `sso.client_id` | string | No | OAuth client ID |
| `login_flow` | list[string] | No | Step-by-step login instructions. Use `$username`, `$password` as placeholders |
| `success_condition.type` | string | No | One of: `url_contains`, `cookie_present`, `text_contains` |
| `success_condition.value` | string | No | Value to check for (URL substring, cookie name, or text) |

## rules (optional)

### rules.avoid / rules.focus

Each rule is a mapping with:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | Human-readable description of the rule |
| `type` | string | Yes | One of: `path`, `endpoint`, `feature`, `parameter` |
| `url_path` | string | No | URL path pattern to match (e.g., `/api`, `/logout`) |
| `method` | string | No | HTTP method (for `endpoint` type, e.g., `DELETE`) |
| `feature` | string | No | Feature name (for `feature` type, e.g., `file_upload`) |

**Avoid rules**: Matching endpoints are skipped entirely (tracked as "skipped" with rule description).

**Focus rules**: Matching endpoints are tested first with extra depth (all vulnerability classes, not just MUST priority).

## reporting (optional)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tester_name` | string | No | Name of the tester or team (used in report header) |
| `organization` | string | No | Organization name |

## MCP Tools

- **`load_engagement_config(engagement_id, config_yaml)`** — Parse and store the config
- **`get_engagement_config(engagement_id)`** — Retrieve stored config (passwords masked)
- **`get_engagement_rules(engagement_id)`** — Get rules formatted for subagent prompts
