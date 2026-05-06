# MCP Compliance Scan

Local-first MCP server for code-review compliance checks. It is designed to run locally over stdio and give review agents deterministic findings before a human or LLM writes the final review.

MCP Compliance Scan is free StoneyTECH software. The project keeps a generic tool name so teams can install it as a purpose-built MCP compliance scanner, while the source and ongoing work are maintained by [StoneyTECH](https://www.stoneytech.net).

See also:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

## MCP Tools

- `review_diff` reviews supplied unified diff text.
- `review_repository` reviews local git changes from a repository path.
- `compliance_checklist` returns the review checklist for a language, framework, or risk profile.
- `standards_catalog` lists the standards used by the compliance engine, optionally filtered by domain.
- `init_audit_db` initializes the local SQLite audit ledger.
- `review_repository_and_persist` reviews local changes and records the audit run.
- `audit_history`, `get_audit_run`, and `audit_trends` query local historical audits.
- `prioritize_audit_run` returns a deterministic critical/high/medium/low priority order for a persisted audit.
- `remediation_plan` returns the dependency-aware fix order for a persisted audit.
- `repository_impact_graph` exports finding, component, standards-control, and finding-to-finding impact edges.
- `sync_github_repositories` inventories GitHub repositories into the local registry.
- `sync_repository_merges` records merged PRs and default-branch commits as merge events.
- `audit_merge` audits the exact `base_sha..merge_commit_sha` diff for one merge event.
- `audit_unprocessed_merges` processes pending merge events in chronological order.
- `merge_audit_history` and `get_merge_audit` inspect merge-event audit history.
- `compliance_report` generates a Markdown or JSON report from the local audit ledger.
- `mcp_security_policy` shows configured local roots and per-tool security effect labels.

The server also exposes Markdown MCP resources:

- `compliance://policy/code-review`
- `compliance://standards/catalog`

## CLI

The package also builds a local/CI CLI:

```bash
node dist/cli.js review --repo . --mode range --base origin/main --target HEAD --profile security --fail-on high
node dist/cli.js audit-merge --repo . --base "$BASE_SHA" --target "$TARGET_SHA" --profile security --format github --fail-on high
node dist/cli.js report --scope portfolio --format markdown
```

The npm binary names are:

- `mcp-compliance-scan`: CLI.
- `mcp-compliance-scan-mcp`: stdio MCP server.

See [docs/cli-and-ci.md](docs/cli-and-ci.md) and [templates/github-actions/mcp-compliance-scan.yml](templates/github-actions/mcp-compliance-scan.yml).

## Standards Baseline

- OWASP ASVS 5.0.0
- OWASP API Security Top 10 2023
- OWASP Top 10 2025
- OWASP REST Security Cheat Sheet
- NIST SSDF SP 800-218 v1.1
- MITRE CWE Top 25 2025
- OpenSSF SLSA 1.2
- OpenSSF Scorecard
- IETF RFC 9700 OAuth 2.0 Security BCP
- Model Context Protocol authorization and security best practices

Findings include standards references in both Markdown and JSON output.

## Priority Model

Findings keep their scanner severity, but remediation uses a deterministic priority band:

- `critical`: fix now; usually secrets, auth bypass, injection, command/code execution, or high-impact chained exposure.
- `high`: fix next; exploitable security, privacy, OAuth/MCP, or supply-chain issues with meaningful exposure.
- `medium`: plan; limited exploitability, incomplete validation, unsafe patterns, or migration risk.
- `low`: backlog; hygiene, test coverage, resilience, or process drift.
- `info`: track; advisory or inventory-only findings.

Priority score is computed from severity, exploitability, external exposure, asset criticality, data sensitivity, dependency centrality, blast radius, standards weight, scanner confidence, dependency impact, and mitigation credit.

The impact graph links:

- `finding -> standard_control` with `VIOLATES_CONTROL`.
- `finding -> component` with `AFFECTS_COMPONENT`.
- `finding -> finding` with `BLOCKS`, `AMPLIFIES`, or `SHARES_ROOT_CAUSE_WITH`.

This lets the MCP answer both "what is most severe?" and "what should we fix first because it unlocks or reduces the most risk?"

## Merge Event Tracking

Merge events are the preferred audit spine. Periodic scans are still useful as a safety net, but normal history should be built from default-branch change events:

```text
repository -> merge_event -> audit_run -> finding -> rule -> standard_control
```

The merge tracker stores:

- GitHub repository inventory and local scan policy.
- Merged PR events with PR number, author, title, base SHA, head SHA, merge commit SHA, and merge time.
- Default-branch commit events that were not already represented by a merged PR.
- Audit status and linked audit run IDs for each merge event.

Set a read-only GitHub token in the local environment before syncing, or authenticate the GitHub CLI with `gh auth login`:

```bash
export MCP_COMPLIANCE_SCAN_GITHUB_TOKEN=...
```

If no token env var is present, the CLI/MCP will try `gh auth token` and use the local keychain-backed GitHub CLI credential.

Then use the MCP tools:

```text
sync_github_repositories
sync_repository_merges(repository: "owner/repo")
audit_unprocessed_merges(repository: "owner/repo")
merge_audit_history(repository: "owner/repo")
```

Repository clones and merge audit history stay under ignored local paths such as `.local/repos/` and `.local/audit/compliance.db`.

## MCP Security Hardening

The MCP server is local-first over stdio, but it still treats model/tool inputs as untrusted. Current guardrails:

- **Allowed local roots:** MCP path inputs such as `repoPath`, `dbPath`, and `checkoutRoot` are validated against configured roots before local read/write/clone operations.
- **Safe git refs:** MCP git ref inputs reject whitespace, option-like refs, range operators, control characters, and unusual punctuation before `git` is invoked.
- **Tool effect labels:** `mcp_security_policy` reports every MCP tool as `local-read`, `local-write`, `network`, `repo-clone`, and/or `untrusted-input`, with the guardrails applied to that tool.
- **Prompt-injection review rule:** diffs are checked for prompt-injection and tool-poisoning phrases such as hidden system/developer instructions, requests to call tools, or attempts to exfiltrate secrets.
- **Untrusted evidence rendering:** Markdown review output labels evidence as untrusted repository content and places it in fenced text blocks so repository text is not presented as instructions.
- **Token handling boundary:** GitHub access uses local environment variables or `gh auth token`; tokens are not persisted to the SQLite audit ledger.

By default, allowed roots are the current working directory, this package root, and this package's `.local/` directory. To scan other local repositories over MCP, set:

```bash
export MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS="/path/to/repos:/path/to/MCP-Compliance-Scan"
```

Use the platform path delimiter for your OS. For a deliberate local-only escape hatch, set `MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT=1`.

This package does not expose a remote HTTP MCP server. If you deploy it remotely, add transport authorization, token audience validation, no token passthrough, secure session handling, SSRF controls, and deployment-level audit logging before use.

## Compliance Reports

Reports are generated from the local SQLite audit ledger, so they can be shared as evidence without putting private repository data in the public source repo. Start with a portfolio report:

```bash
node dist/cli.js report --scope portfolio --db .local/audit/compliance.db
```

Other scopes:

- `repository`: one registered repository, with `--repository owner/repo`.
- `audit_run`: one historical audit, with `--audit-run-id audit_...`.
- `merge_window`: merge events from the last `--days`, optionally filtered with `--repository owner/repo`.

Report sections include executive summary, repositories covered, merge/audit coverage, findings by priority, findings by standards control, critical/high remediation queue, recent improvements/regressions, pending unaudited merges, standards snapshot hashes, and evidence metadata.

## Local Setup

```bash
npm install
npm run build
```

Example MCP client config:

```json
{
  "mcpServers": {
    "mcp-compliance-scan": {
      "command": "node",
      "args": ["/absolute/path/to/MCP-Compliance-Scan/dist/index.js"]
    }
  }
}
```

For development:

```bash
npm run dev
npm run cli -- help
```

## Review Profiles

- `standard`: balanced review for application code.
- `strict`: treats policy bypasses and missing tests with higher urgency.
- `security`: emphasizes secrets, auth, network, injection, and logging risks.

## Verification

```bash
npm test
npm run build
npm run check:standards
```

For n8n or other schedulers, use `npm run check:standards:json` and parse the `summary.updateCount` and `summary.errorCount` fields.

## Local Audit History

The audit ledger is SQLite and local-only by default:

```bash
sqlite3 .local/audit/compliance.db < schema/audit-ledger.sql
```

MCP clients can also initialize and write to it with `init_audit_db`, `review_repository_and_persist`, and `audit_merge`. The database stores repository policies, merge events, audit manifests, repo snapshots, rule pack identifiers, standards snapshot hashes, findings, priority metadata, impact edges, and standards-control mappings.

## Public Repo Boundary

This repo is public-safe by design. Keep only code, schemas, docs, and sanitized workflow templates in GitHub. Keep local n8n runtime data, credentials, execution logs, audit databases, and generated reports in ignored local paths such as `.local/`.

See [docs/public-repo-local-data.md](docs/public-repo-local-data.md).
