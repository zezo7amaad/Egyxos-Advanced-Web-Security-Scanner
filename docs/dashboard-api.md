# Dashboard API

The dashboard is served by the native Node HTTP server:

```bash
npm install
npm run build
npm run dashboard
```

Open `http://localhost:4173`. The server serves `dashboard/`, the copied logo at
`assets/logo.svg`, and the authenticated API under `/api`.

## Authentication setup

The repository did not previously contain authentication. The dashboard therefore
uses an environment-configured user directory and short-lived, in-memory sessions.
Passwords are never sent back to the browser and session identifiers are stored in
HttpOnly, SameSite cookies. Use HTTPS in production so the server can set `Secure`.

Generate a password hash with the built auth helper:

```bash
node --input-type=module -e "import { hashPassword } from './dist/auth.js'; console.log(hashPassword(process.argv[1]))" "replace-this-password"
```

Configure users before starting the server:

```bash
export EGYXOS_DASHBOARD_USERS_JSON='[
  {"id":"analyst-1","username":"analyst@example.test","passwordHash":"scrypt$...","role":"analyst","displayName":"Security Analyst"},
  {"id":"approver-1","username":"approver@example.test","passwordHash":"scrypt$...","role":"approver","displayName":"Assessment Lead"}
]'
```

Roles are enforced server-side:

- `viewer`: read-only projects, scope, assessments, findings, activity, and reports
- `analyst`: viewer access plus finding status and remediation updates
- `approver`: analyst access plus assessment requests and approval workflows
- `admin`: all dashboard permissions

If the variable is missing or invalid, login returns an explicit service configuration
error. No credentials are hard-coded.

## Endpoints

All endpoints except login require the dashboard session cookie. Mutating requests
also require the `X-CSRF-Token` returned by `/api/auth/login` or `/api/auth/me`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/auth/login` | Authenticate and create a session |
| GET | `/api/auth/me` | Return the signed-in identity and CSRF token |
| POST | `/api/auth/logout` | Revoke the in-memory session |
| GET | `/api/projects` | List filesystem-backed projects without local paths |
| GET | `/api/projects/:id` | Read one project |
| GET | `/api/projects/:id/scope` | Read approved targets |
| GET | `/api/projects/:id/sessions` | Read assessment sessions |
| GET | `/api/projects/:id/findings` | Read project findings |
| GET | `/api/projects/:id/reports` | List generated report files |
| GET | `/api/scans` | List assessment sessions across projects |
| POST | `/api/scans` | Validate scope and create a planned assessment request |
| GET | `/api/approvals` | List approval records attached to assessment sessions |
| POST | `/api/approvals` | Create a pending, scope-validated approval request |
| PATCH | `/api/approvals/:id` | Approve or deny a request as an approver |
| GET | `/api/findings` | List findings, optionally filtered by `project` |
| GET | `/api/findings/:id` | Read one finding |
| PATCH | `/api/findings/:id` | Update supported finding review fields |
| GET | `/api/reports` | List generated Markdown, HTML, and JSON reports |
| GET | `/api/activity` | Read redacted audit events |
| GET | `/api/tools` | Read the scanner tool registry |

`POST /api/scans` never starts a scan merely because the dashboard was opened. It
validates the target against the active project's configured scope and records a
planned session. Tool execution remains an explicit scanner operation requiring the
existing approval gate; the response says so directly rather than claiming execution.

Evidence is served from the scanner's existing finding records. Tool output and AI
analysis are not treated as verified facts by the UI.
