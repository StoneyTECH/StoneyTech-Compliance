# Public Repo, Local Data

The public repo should contain code, schemas, sanitized templates, docs, and tests. It should not contain your operational data.

## Lives In GitHub

- MCP server source code.
- Standards catalog code and policy documents.
- SQLite schema in `schema/audit-ledger.sql`.
- Local n8n Docker Compose template in `deploy/local-n8n/`.
- Sanitized n8n workflow templates in `workflows/n8n/`.
- Example environment files such as `.env.example`.

## Stays Local

- n8n runtime data: workflows as actually installed, credentials, execution history, and n8n's internal SQLite database.
- n8n encryption key.
- Local audit ledger databases.
- Local repository clones used for merge auditing.
- Audit run exports, merge histories, generated reports, logs, and one-off local data.
- Any Slack, GitHub, email, OAuth, or API credentials.

Ignored local paths include `.local/`, `local/`, `data/`, `audit-runs/`, `reports/`, `exports/`, `.n8n/`, `n8n-data/`, and SQLite database files.

## Recommended Local Layout

```text
MCP-Compliance-Scan/
  deploy/local-n8n/          # committed template
  schema/audit-ledger.sql    # committed schema
  workflows/n8n/             # committed sanitized templates
  .local/
    n8n/                     # local n8n runtime data, ignored
    audit/
      compliance.db          # local SQLite audit ledger, ignored
    repos/                   # local repository clone cache, ignored
    reports/                 # local generated outputs, ignored
```

## Local n8n Runtime

Copy the example env file, set a local encryption key, then start n8n:

```bash
cp deploy/local-n8n/.env.example deploy/local-n8n/.env
openssl rand -hex 32
docker compose --env-file deploy/local-n8n/.env -f deploy/local-n8n/docker-compose.yml up -d
```

Open `http://localhost:5678`, import `workflows/n8n/standards-monitor.template.json`, and wire the notification node to your local Slack/email/GitHub credential.

The n8n docs note that Docker stores n8n's SQLite database and encryption key under `/home/node/.n8n`; this compose file maps that to `.local/n8n`, which is ignored.

## Local SQLite Ledger

Create a local audit DB with the schema:

```bash
mkdir -p .local/audit
sqlite3 .local/audit/compliance.db < schema/audit-ledger.sql
```

Or initialize it through MCP with `init_audit_db`.

The schema is committed because it is public-safe. The actual `.db` file is ignored because it will contain private repository names, merge events, commit SHAs, PR metadata, audit findings, paths, waivers, priority scores, dependency/impact edges, and history.

The priority and graph model is safe to publish as code. The sensitive part is the populated graph, because it can reveal which private repositories have specific weaknesses and which standards controls they violate.

## GitHub Merge Tracking

GitHub tokens stay in your local environment, for example `MCP_COMPLIANCE_SCAN_GITHUB_TOKEN`. Do not put real tokens into MCP config committed to this repo, workflow templates, or n8n exports.

The committed code can know how to poll GitHub, classify repositories, and audit merge diffs. The local database stores the actual repository list and merge timeline.
