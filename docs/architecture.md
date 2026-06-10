# Architecture

Dristi is a dual-interface security testing platform: an **MCP server** (94 tools for methodology, tracking, findings management) and an **OpenCode agent bundle** (72 auto-loading agents + 14 commands for bug hunting tradecraft).

```
┌─────────────────────────────────────────────────────────┐
│                    USER (OpenCode / LLM)                 │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌──────────────────┐    ┌──────────────────────────┐
│  Dristi MCP      │    │  OpenCode Agents (72)    │
│  Server (94 tools)│    │  + Commands (14)         │
│  ──────────────── │    │  ──────────────────────  │
│  • WSTG v4.2     │    │  • hunt-xss, hunt-sqli   │
│  • H1 8,376+ rpts│    │  • bb-methodology        │
│  • WAF bypass    │    │  • triage-validation     │
│  • Findings DB    │    │  • offensive-osint       │
│  • Engagement     │    │  • m365-entra-attack     │
│    management     │    │  • ... 64 more           │
│  • Phase gates    │    │                          │
│  • Reporting      │    └──────────┬───────────────┘
│  • Knowledge      │               │
│    graph          │               │ triggers
└────────┬──────────┘               ▼
         │              ┌──────────────────────────┐
         │              │  Burp Suite MCP Server   │
         │              │  (HTTP request execution) │
         │              └──────────────────────────┘
         ▼
┌─────────────────────────────────────────────────────┐
│              Storage (server/data/)                   │
│  findings/ tracking/ scope/ checkpoints/ events/     │
│  exploitation-queues/ deliverables/ configs/         │
│  task-trees/ priority-queues/ waf-data/              │
│  knowledge-graphs/ gate-tracking/ qa-tracking/       │
│  code-analysis/                                       │
└─────────────────────────────────────────────────────┘
```

## Components

### 1. MCP Server (`server/server.py`)

The core methodology engine. 94 tools organized into:

| Category | Tools | Purpose |
|----------|-------|---------|
| Knowledge Base | 5 | WSTG test cases, search, payloads |
| Technique Guides | 3 | PortSwigger Academy, WAF bypass |
| Engagement Management | 4 | Scope, config, YAML parsing |
| Findings & Evidence | 6 | Log, update, query findings |
| Test Coverage | 4 | Track tests and tools |
| Phase Gates & QA | 4 | Gate checks, QA/judge reviews |
| Report Generation | 1 | Auto-generate markdown reports |
| Exploitation | 6 | Queue, classify, mark exploited |
| Code Analysis | 3 | Source code review pipeline |
| Checkpoint & Resume | 4 | Save/restore engagement state |
| Task Tree | 6 | Hierarchical planning |
| Browser Automation | 1 | Isolated profiles |
| Git Checkpointing | 2 | Git snapshots |
| WAF Evasion | 3 | Fingerprint + bypass payloads |
| Knowledge Graph | 5 | Node/edge graph + chaining |
| Findings Database | 13 | SQLite-backed CRUD + graph |
| Utility | 9 | Status, audit, prioritize, verify |

### 2. OpenCode Agents (72)

Agents auto-load when you describe what you're testing. Each is a `SKILL.md` file in `.opencode/agents/<name>/` with YAML frontmatter and markdown body.

| Domain | Count | Agent names |
|--------|-------|-------------|
| Recon & OSINT | 4 | `offensive-osint`, `web2-recon`, `osint-methodology`, `bb-local-toolkit` |
| Web App Hunting | 49 | `hunt-xss`, `hunt-sqli`, `hunt-idor`, `hunt-ssrf`, `hunt-rce`, `hunt-file-upload`, `hunt-graphql`, `hunt-xxe`, `hunt-ssti`, `hunt-csrf`, `hunt-oauth`, `hunt-saml`, `hunt-ato`, `hunt-mfa-bypass`, `hunt-auth-bypass`, `hunt-brute-force`, `hunt-cors`, `hunt-deserialization`, `hunt-dom`, `hunt-host-header`, `hunt-http-smuggling`, `hunt-ldap`, `hunt-lfi`, `hunt-nosqli`, `hunt-open-redirect`, `hunt-session`, `hunt-source-leak`, `hunt-subdomain`, `hunt-tls-network`, `hunt-websocket`, `hunt-api-misconfig`, `hunt-cache-poison`, `hunt-cloud-misconfig`, `hunt-business-logic`, `hunt-cicd`, `hunt-grpc`, `hunt-k8s`, `hunt-laravel`, `hunt-nextjs`, `hunt-nodejs`, `hunt-springboot`, `hunt-aspnet`, `hunt-sharepoint`, `hunt-ntlm-info`, `hunt-misc`, `hunt-race-condition`, `hunt-llm-ai`, `hunt-dispatch`, `web2-vuln-classes` |
| Enterprise Platform | 7 | `m365-entra-attack`, `okta-attack`, `cloud-iam-deep`, `vmware-vcenter-attack`, `enterprise-vpn-attack`, `apk-redteam-pipeline`, `supply-chain-attack-recon` |
| Red Team Tradecraft | 2 | `redteam-mindset`, `mid-engagement-ir-detection` |
| Workflow & Validation | 5 | `bb-methodology`, `bug-bounty`, `triage-validation`, `security-arsenal`, `hunt-dispatch` |
| Reporting & Hygiene | 4 | `report-writing`, `bugcrowd-reporting`, `evidence-hygiene`, `redteam-report-template` |
| Specialized | 2 | `web3-audit`, `meme-coin-audit` |

### 3. Commands (14)

Slash commands in `.opencode/commands/` that route to specific agents:

| Command | Routes to | Purpose |
|---------|-----------|---------|
| `/recon <target>` | offensive-osint, web2-recon | Run recon pipeline |
| `/hunt <target>` | hunt-dispatch + relevant hunt-* | Start hunting |
| `/triage` | triage-validation | Quick 7-Question Gate |
| `/validate` | triage-validation | Full 7Q Gate + 4 gates |
| `/report` | report-writing + bugcrowd-reporting | Draft report |
| `/chain` | chain-building agents | Build exploit chain |
| `/autopilot <target>` | multiple agents | Autonomous hunt loop |
| `/scope <asset>` | bb-methodology | Check asset scope |
| `/surface <target>` | offensive-osint | Ranked attack surface |
| `/intel <target>` | intel engine | CVE/disclosed-report intel |
| `/pickup <target>` | multiple agents | Resume previous hunt |
| `/remember` | memory tools | Log finding to hunt memory |
| `/memory-gc` | memory tools | Compact/rotate memory |
| `/token-scan` | meme-coin-audit | Token security scan |

### 4. Scripts & Tools (`scripts/`)

| Path | Purpose |
|------|---------|
| `scripts/bughunt.py` | Terminal-native CLI runner |
| `scripts/hunt.sh` | Engagement-folder scaffolder |
| `scripts/install.sh` | Installer |
| `scripts/convert_skills.py` | Skill-to-agent converter |
| `scripts/convert_commands.py` | Command converter |
| `scripts/reconnect-burp.sh` | Burp MCP reconnection |
| `scripts/dork_runner.py` | Google dork automation |
| `scripts/full_hunt.sh` | Full hunt pipeline |
| `scripts/tools/` (37 files) | Scanners, testers, helpers |

### 5. Wordlists (`knowledge/wordlists/`)

Supplementary wordlists for recon and fuzzing: API endpoints, common paths, parameters, sensitive files.

### 6. Skills Reference (`skills/`)

Reference copies of all agent SKILL.md files (74 total). The active versions are in `.opencode/agents/`.

---

## How agents auto-trigger

1. You describe what you're testing in plain English
2. OpenCode scans the `description` field in each agent's YAML frontmatter
3. Matching agents load into context
4. The LLM uses the agent's content to guide testing

Example: *"I see a `?url=` parameter on this endpoint"* → `hunt-ssrf` loads automatically. You don't invoke it by name.

---

## Agent-loading mechanics

- **Auto-trigger**: Agents load when their `description` matches your prompt
- **Progressive disclosure**: Large agents keep SKILL.md lean, put detailed content in subfolders
- **Commands**: Explicit invocations (`/triage`, `/report`, etc.) force-load specific agents

---

## What's NOT in the bundle

- **No automated exploitation** — guides hunting, doesn't fire payloads automatically
- **No CI/CD integration** — designed for individual researchers, not scanning pipelines
- **iOS testing not covered** — Android only via `apk-redteam-pipeline`
