<p align="center">
  <img src="assets/egyxos_pyramid_sword_transparent.png" alt="Egyxos Advanced Web Security Scanner logo" width="320">
</p>

# Egyxos Advanced Web Security Scanner

Egyxos Advanced Web Security Scanner is an AI-assisted security assessment platform designed for authorized security testing and evidence-driven review. It combines project management, human approval boundaries, scope enforcement, tool orchestration, findings tracking, and reporting in a single command-line experience.

## TM471-A graduation project platform

This repository now includes the Python 3.11+ FastAPI platform specified by the
TM471-A proposal, **"Egyxos: An AI-Assisted Web Reconnaissance and Vulnerability
Assessment Platform"**. The implementation keeps the original TypeScript CLI
available, while the academic platform lives under `app/`.

The four-stage workflow is:

1. Scope validation against an explicit allowlist
2. Subdomain discovery with `subfinder`
3. Live-host and technology probing with `httpx`
4. Vulnerability scanning with `nuclei`, paused behind an approval gate

```mermaid
flowchart LR
  Scope[Authorized scope] --> Gate{Scope validation}
  Gate -->|allowed| Plan[Scan session]
  Gate -->|blocked| Audit[Immutable audit event]
  Plan --> Approval{Nuclei or active mode?}
  Approval -->|pending| Human[Operator approval]
  Human --> Pipeline[subfinder -> httpx -> nuclei]
  Approval -->|not required| Pipeline
  Pipeline --> Normalize[Unified findings]
  Normalize --> AI[Gemini/Ollama or deterministic fallback]
  AI --> Reports[Markdown / HTML / JSON]
  Normalize --> Dashboard[FastAPI dashboard]
```

### Run the FastAPI platform locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`. The dashboard is pre-populated with a local
evaluation workflow, but it does not claim that a scan ran. Missing external
security binaries use safe demo-mode observations. Set `DEMO_MODE=false` to
disable that fallback.

Configuration is read from environment variables or `.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./egyxos.db` | SQLite or PostgreSQL SQLAlchemy URL |
| `LAB_MODE` | `true` | Identifies local evaluation mode |
| `DEMO_MODE` | `true` | Safe fallback when security binaries are unavailable |
| `GEMINI_API_KEY` | unset | Optional Gemini triage provider |
| `GEMINI_MODEL` | `gemini-2.0-flash` | Gemini model |
| `OLLAMA_URL` | unset | Optional local Ollama endpoint |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model |
| `REPORTS_DIR` | `reports` | Generated report directory |

Without an AI provider, the deterministic analyzer labels evidence conservatively
for reproducible tests. AI output is always reported separately from raw evidence.

### Local evaluation lab

The compose file binds every service to loopback only:

```bash
docker compose up --build
```

- Egyxos API and dashboard: `http://127.0.0.1:8000`
- OWASP Juice Shop: `http://127.0.0.1:3000`
- DVWA: `http://127.0.0.1:8080`

Use only these local containers for evaluation unless you have separate written
authorization for another target.

### Verification

```bash
pytest -v
```

The pytest suite covers out-of-scope blocking and audit logging, approval gates,
demo-mode pipeline execution, AI triage persistence, and all three report formats.

The API reference is in [`docs/dashboard-api.md`](docs/dashboard-api.md). The
FastAPI routes are versioned under `/api/v1`, including `/api/v1/scopes`,
`/api/v1/scans`, `/api/v1/findings`, `/api/v1/audit`, and
`/api/v1/reports/{scan_id}`.

## What is Egyxos Advanced Web Security Scanner?

Egyxos Advanced Web Security Scanner helps teams run structured red-team and security assessment workflows against approved targets while preserving strict safety boundaries. The platform keeps a human in the loop for sensitive actions, stores evidence in a local-first database, and produces shareable reports with technical findings and remediation guidance.

## Features

- Project-aware assessment workflows
- Session memory and state persistence
- Scope validation for in-scope targets only
- Approval gates for high-impact actions
- Tool registry for recon and testing adapters
- Findings engine with severity and confidence tracking
- Evidence-based reporting in Markdown, HTML, and JSON
- AI provider abstraction with provider and model routing
- Gemini-powered bug bounty analysis skills
- Doctor command to validate configuration and dependencies
- Dry-run preview for safe command planning

## Architecture

The implementation follows a modular design:

- CLI entrypoint for operator control
- Project and session managers
- Scope and approval engine
- Tool registry and adapters
- Agent orchestration layer
- Findings and evidence storage
- Reporting and documentation generation

## Installation

### Linux installation

```bash
sudo apt update
sudo apt install -y git curl build-essential
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

After cloning the repository, run the included installer from its root:

```bash
chmod +x scripts/install-linux.sh
./scripts/install-linux.sh
```

The installer checks for Node.js 20+, runs `npm install`, builds the TypeScript CLI, and runs `npm link`. It does not install external security tools or execute scans.

### Clone and build

```bash
git clone https://github.com/zezo7amaad/Egyxos-Red-Team.git
cd Egyxos-Red-Team
npm install
npm run build
```

Install the CLI globally from the local checkout:

```bash
sudo npm link
egyxos-redteam --help
```

For local development without a global link:

```bash
npx tsx src/index.ts --help
```

### Windows PowerShell

```bash
npm install
npm run build
npm link
```

## Quick Start

```bash
egyxos-redteam project create demo
egyxos-redteam project open demo
egyxos-redteam scope add example.com
egyxos-redteam session start
egyxos-redteam tools list
egyxos-redteam doctor
```

## CLI

The CLI exposes the primary security-assessment workflows:

```bash
egyxos-redteam

egyxos-redteam project create acme
egyxos-redteam project list
egyxos-redteam project open acme

egyxos-redteam scope show
egyxos-redteam scope add example.com

egyxos-redteam session start
egyxos-redteam session list
egyxos-redteam session resume <id>

egyxos-redteam recon start
egyxos-redteam tools list
egyxos-redteam skills list
egyxos-redteam skills curriculum
egyxos-redteam ai ask bug-bounty-triage "Review these authorized observations"
egyxos-redteam ai scan bug-bounty-triage example.com --approve
egyxos-redteam findings list
egyxos-redteam report generate
egyxos-redteam doctor
egyxos-redteam config show
```

## Projects

Projects are created under the local storage root and include folders for scope, sessions, evidence, findings, notes, and reports.

## Sessions

Sessions capture the current assessment objective, target, tool activity, approvals, and session-state transitions.

## Reconnaissance

Egyxos Advanced Web Security Scanner includes a framework for recon tasks such as service discovery, URL enumeration, technology detection, subdomain discovery, and API discovery through adapters.

Preview a passive subdomain discovery action:

```bash
egyxos-redteam scope add example.com
egyxos-redteam recon start
```

The current CLI displays a scope-checked command preview. External tools are not executed automatically by the CLI yet.

## Security Testing

The platform supports structured web and API testing patterns while requiring explicit approval for potentially impactful actions.

## AI Providers

The initial AI provider is Google Gemini through the Gemini REST API. Credentials are loaded from environment variables and never stored in project files:

```bash
export GEMINI_API_KEY="your-key"
export GEMINI_MODEL="gemini-3.6-flash"
```

If you previously configured the retired `gemini-2.0-flash` model, replace it in the current shell:

```bash
export GEMINI_MODEL="gemini-3.6-flash"
```

PowerShell:

```powershell
$env:GEMINI_API_KEY = "your-key"
$env:GEMINI_MODEL = "gemini-3.6-flash"
```

Ask Gemini to analyze authorized evidence with a named security skill:

```bash
egyxos-redteam skills list
egyxos-redteam ai ask bug-bounty-triage "Review this authorized HTTP response for security issues: ..."
egyxos-redteam ai ask finding-report-writer "Draft a report from this validated evidence: ..."
```

The provider sends only the prompt supplied to the command. Do not paste secrets, credentials, private tokens, or unnecessary personal data into prompts.

Gemini availability errors such as HTTP `503` or rate limits are retried up to two times with a short backoff. If the provider remains unavailable, wait and run the command again rather than increasing scan activity.

## AI command reference

Configure Gemini in the current shell before using AI commands:

```bash
export GEMINI_API_KEY="YOUR_REPLACEMENT_KEY"
export GEMINI_MODEL="gemini-3.6-flash"
```

Check the provider configuration:

```bash
egyxos-redteam config show
egyxos-redteam doctor
```

List the available AI security skills:

```bash
egyxos-redteam skills list
```

Display the authorized-security curriculum injected into skill prompts:

```bash
egyxos-redteam skills curriculum
```

Ask Gemini to analyze supplied, sanitized evidence:

```bash
egyxos-redteam ai ask bug-bounty-triage "Analyze this authorized evidence: two tester-controlled accounts were used in staging.example.test. Account A received Account B's synthetic profile record. Credentials and tokens were redacted. Classify the observation, confidence, impact, safe validation, and remediation."
```

Review web exposure evidence:

```bash
egyxos-redteam ai ask web-exposure-review "Review these authorized read-only response headers from staging.example.test and identify missing security controls without claiming exploitability."
```

Review API authorization evidence:

```bash
egyxos-redteam ai ask api-review "Analyze this authorized API observation from staging.example.test for access-control weaknesses using only tester-controlled records."
```

Review XSS evidence:

```bash
egyxos-redteam ai ask xss-review "Analyze this authorized input/output evidence. A harmless marker was reflected in an approved staging test account. Determine the output context, encoding, confidence, and safe next step."
```

Review SQL injection evidence:

```bash
egyxos-redteam ai ask sqli-review "Analyze this authorized SQL input evidence from a staging test record. Compare the sanitized baseline and error response, identify what is proven, and recommend low-impact validation."
```

Review possible subdomain takeover evidence:

```bash
egyxos-redteam ai ask subdomain-takeover-review "Analyze this authorized DNS evidence. A scoped test subdomain has a CNAME pointing to an unassigned provider resource and returns a provider-specific error. Treat takeover as unconfirmed and recommend safe verification."
```

Draft a report from validated evidence:

```bash
egyxos-redteam ai ask finding-report-writer "Draft an evidence-backed report from this authorized, validated observation. Include title, affected asset, severity, confidence, reproduction, impact, evidence, and remediation."
```

Run the bounded tool-to-AI scan workflow:

```bash
egyxos-redteam project open authorized-lab
egyxos-redteam scope add example.com
egyxos-redteam scope show
egyxos-redteam ai scan bug-bounty-triage example.com --approve
```

The scan pipeline is:

```text
scope validation -> subfinder -> httpx -> approved Nuclei -> Gemini analysis -> Markdown report
```

Reports are saved under:

```text
~/.egyxos-redteam/reports/
```

The `--approve` flag is required because Nuclei performs active security checks. AI commands do not authorize a target, bypass scope, access real users' data, extract credentials, or perform destructive testing. Use only written-authorized targets and sanitized evidence.

## Bug bounty skills

Built-in skills provide constrained operating guidance for authorized programs:

- `bug-bounty-triage` - classify observations into hypotheses and validated findings
- `passive-asset-discovery` - organize approved subdomain and service discovery
- `web-exposure-review` - review headers, exposure, and error behavior
- `api-review` - analyze authorized API documentation and responses
- `xss-review` - review authorized input/output behavior for XSS hypotheses
- `sqli-review` - review authorized input/error behavior for SQL injection hypotheses
- `subdomain-takeover-review` - review authorized DNS and provider evidence for dangling services
- `finding-report-writer` - draft evidence-backed vulnerability reports

List skills with:

```bash
egyxos-redteam skills list
```

Skills do not grant authorization and do not bypass scope or approval controls. They are designed to help analyze evidence and plan low-impact, permitted testing; they do not autonomously exploit targets.

## AI scan and reporting

Run a bounded scan against a target already present in the active project scope:

```bash
egyxos-redteam scope add example.com
egyxos-redteam ai scan bug-bounty-triage example.com --approve
```

The workflow runs `subfinder`, `httpx`, and Nuclei with fixed timeouts and sends their completed output to the configured Gemini provider for evidence-only triage. The prompt includes the local scope and authorization result and explicitly tells Gemini not to perform additional network activity. Nuclei requires the explicit `--approve` flag. The resulting AI assessment is written to `~/.egyxos-redteam/reports/`.
Tool output is captured through temporary files and capped before AI analysis, so verbose Nuclei JSONL output does not exhaust the process buffer (`ENOBUFS`).
For faster repeat scans, update templates separately and skip that step during each scan:

```bash
nuclei -update-templates
export EGYXOS_SKIP_NUCLEI_TEMPLATE_UPDATE=1
export EGYXOS_NUCLEI_SEVERITY=medium,high,critical
export EGYXOS_NUCLEI_CONCURRENCY=50
export EGYXOS_NUCLEI_RATE_LIMIT=150
egyxos-redteam ai scan bug-bounty-triage example.com --approve
```

Only use higher concurrency or rate limits when the authorized target and your network can handle them. Remove `EGYXOS_SKIP_NUCLEI_TEMPLATE_UPDATE` or unset it when you want each scan to refresh templates.

Before scanning, EGYXOS runs `nuclei -update-templates` so the approved scan uses the installed current template set. Template updates and scanning are bounded and require the same explicit `--approve` scan authorization.

Nuclei has a bounded default timeout of 10 minutes because template loading and multi-host scans can take longer than discovery tools. Override it for the current shell when needed:

```bash
export EGYXOS_NUCLEI_TIMEOUT_MS=900000
```

Template updates use a separate 5-minute default timeout:

```bash
export EGYXOS_NUCLEI_TEMPLATE_TIMEOUT_MS=600000
```

Discovery tools use a 2-minute default timeout and can be adjusted with:

```bash
export EGYXOS_TOOL_TIMEOUT_MS=300000
```

This command does not perform exploitation, credential testing, data extraction, state-changing requests, or out-of-scope scanning. It requires written authorization and an accurate project scope.

### Tool name collision: `httpx`

EGYXOS requires ProjectDiscovery's `httpx` binary. Python's `httpx` package can also install a command named `httpx`, but it does not support ProjectDiscovery flags such as `-l`, `-silent`, or `-title`. If a scan reports that `httpx` has no `-l` option, install ProjectDiscovery httpx and ensure its binary appears first on PATH:

```bash
command -v httpx
httpx -version
```

The output should identify ProjectDiscovery httpx. EGYXOS detects this collision and reports a direct remediation instead of passing through the raw CLI usage error.

## Security training curriculum

EGYXOS does not fine-tune or retrain Gemini locally. Instead, each AI request receives a structured authorized-security curriculum covering:

- authorization and scope enforcement
- passive reconnaissance
- web and API analysis
- safe BOLA/IDOR validation with owned test accounts
- controlled XSS and SQL injection review
- passive subdomain takeover analysis without claiming third-party resources
- evidence and confidence handling
- severity classification
- remediation and report writing

View the curriculum:

```bash
egyxos-redteam skills curriculum
```

## Tools

Available adapters include:

- httpx
- katana
- subfinder
- ffuf
- sqlmap
- nmap
- nuclei
- curl
- dig
- whois

### Compact tool command reference

Command previews prefer compact flags where each tool supports them:

| Tool | Compact command preview | Flag meaning |
| --- | --- | --- |
| `httpx` | `httpx -u TARGET -silent -title` | `-u` URL, `-silent` reduced output, `-title` page title |
| `katana` | `katana -u TARGET -silent` | `-u` target URL, `-silent` reduced output |
| `subfinder` | `subfinder -d DOMAIN -silent` | `-d` domain, `-silent` reduced output |
| `ffuf` | `ffuf -u TARGET/FUZZ -w WORDLIST -s` | `-u` URL pattern, `-w` wordlist, `-s` silent output |
| `sqlmap` | `sqlmap -u TARGET --batch --smart` | `-u` URL, `--batch` non-interactive mode, `--smart` smart checks |
| `nmap` | `nmap -sV -T3 TARGET` | `-sV` service detection, `-T3` moderate timing |
| `nuclei` | `nuclei -u TARGET -v ...` | `-u` target URL, `-v` verbose output |
| `curl` | `curl -sSIL TARGET` | `-s` silent, `-S` show errors, `-I` headers, `-L` redirects |
| `dig` | `dig +short DOMAIN` | `+short` concise DNS output |
| `whois` | `whois DOMAIN` | Domain registration lookup |

`nuclei` is intended for approved vulnerability-template checks and `subfinder` is intended for passive subdomain discovery. All tools are listed by `egyxos-redteam tools list`, checked by `egyxos-redteam doctor`, and represented by scope-aware command previews. External tools are never installed or executed silently.

The registry exposes availability checks and dry-run action previews.

The EGYXOS CLI command itself must still come first. For example:

```bash
egyxos-redteam tools list
egyxos-redteam scope show
egyxos-redteam skills list
egyxos-redteam ai ask bug-bounty-triage "Review this authorized evidence"
```

The short flags above are previews for the external security tools. They are not standalone EGYXOS commands.

## Skills

The project supports a modular skill registry for reconnaissance, web, API, authentication, authorization, analysis, and reporting tasks. Skills are dynamically discoverable through the core registry.

## Findings

Findings are represented as structured records containing severity, confidence, target, endpoint, reproduction, evidence, and remediation guidance. Findings are never upgraded to confirmed without enough evidence.

## Reports

Reports can be generated in Markdown, HTML, and JSON. The report engine summarizes the executive overview, scope, findings, evidence, and risk profile for the assessment.

## Configuration

Egyxos Advanced Web Security Scanner stores configuration under the local user directory:

```text
~/.egyxos-redteam/config.json
```

The configuration supports project selection, provider/model configuration, scope defaults, storage path overrides, and tool enablement.

The default data directory is:

```text
~/.egyxos-redteam/
```

Override it with:

```bash
export EGYXOS_STORAGE="$HOME/.egyxos-data"
```

PowerShell:

```powershell
$env:EGYXOS_STORAGE = "C:\egyxos-data"
```

## Security Model

The implementation intentionally enforces the following boundaries:

- explicit authorization before risky actions
- least-privilege defaults
- scope validation
- auditability via session and action logs
- no secret leakage in logs
- safe dry-run planning

## Development

```bash
npm install
npm run build
npm test
```

## Dashboard preview

The repository includes a static operations dashboard in `dashboard/` for reviewing
sample assessment data, findings, evidence quality, scan state, recent activity, and
authorization scope. Open `dashboard/index.html` in a browser to preview it. All
records are explicitly marked as sample data; the preview does not execute scans or
imply that any target has been tested.

## Dashboard server

The dashboard can also run with the filesystem-backed API and protected login flow:

```bash
npm run build
npm run dashboard
```

Then open `http://localhost:4173`. Configure `EGYXOS_DASHBOARD_USERS_JSON` with
scrypt password hashes before signing in. The complete endpoint list, role model,
cookie/CSRF behavior, and authentication setup are documented in
[`docs/dashboard-api.md`](docs/dashboard-api.md). Without configured users, the
server intentionally shows an authentication configuration error instead of
providing a decorative or unprotected login.

## Testing

Vitest is used for the project test suite, including agent, scope, reporting, project, and tool validation tests.

## Scheduled GitHub Actions scan

The repository includes `.github/workflows/example-com-security-scan.yml`, which runs daily at `00:00 UTC`. It performs passive subdomain enumeration with `subfinder`, then runs Nuclei against the discovered list. It can also be started manually from the Actions tab with a different authorized domain. Results are uploaded as an `example-com-scan-reports` artifact for 14 days.

The workflow uses these compact tool commands:

```bash
subfinder -d example.com -silent
nuclei -l scan_results/example.com_subdomains.txt -v -severity info,low,medium,high,critical -jsonl
```

Only run this workflow against domains you own or have explicit permission to assess. The workflow uses read-only repository permissions and validates the manually supplied domain before scanning.

## Contributing

Contributions are welcome. Please keep the implementation original and aligned with the product identity. Avoid reusing or copying vendor implementation details from the reference project.

## License

MIT.
