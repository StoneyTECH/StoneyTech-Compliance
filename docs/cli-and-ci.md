# CLI And CI

The compliance tool can run without Codex as a local CLI or GitHub Actions gate.

## Build

```bash
npm install
npm run build
```

The package exposes two binaries:

- `mcp-compliance-scan`: local/CI CLI.
- `mcp-compliance-scan-mcp`: stdio MCP server.

## Local Review

Review current working-tree changes:

```bash
node dist/cli.js review --repo . --profile security
```

Review a pull-request style range:

```bash
node dist/cli.js review \
  --repo . \
  --mode range \
  --base origin/main \
  --target HEAD \
  --profile security \
  --fail-on high
```

Review an exact merge or push diff:

```bash
node dist/cli.js audit-merge \
  --repo . \
  --base "$BASE_SHA" \
  --target "$TARGET_SHA" \
  --profile security \
  --fail-on high
```

## Output Formats

- `--format markdown`: human-readable terminal output.
- `--format json`: machine-readable report with priority plan.
- `--format github`: GitHub Actions annotations.

## Failure Policy

Use `--fail-on` to decide when CI exits nonzero:

- `none`: never fail from findings.
- `critical`: fail on critical only.
- `high`: fail on critical or high.
- `medium`: fail on critical, high, or medium.
- `low`: fail on critical, high, medium, or low.
- `info`: fail on any finding.

The recommended CI default is `--fail-on high`.

## Persisting Local History

For local audit history, add `--persist` and optionally `--db`:

```bash
node dist/cli.js review \
  --repo . \
  --mode range \
  --base origin/main \
  --target HEAD \
  --profile security \
  --persist \
  --db .local/audit/compliance.db
```

Then inspect:

```bash
node dist/cli.js history --db .local/audit/compliance.db
node dist/cli.js trends --db .local/audit/compliance.db
```

## Compliance Reports

Generate a Markdown report from the local audit ledger:

```bash
node dist/cli.js report \
  --scope portfolio \
  --db .local/audit/compliance.db
```

Generate JSON for a dashboard or website:

```bash
node dist/cli.js report \
  --scope portfolio \
  --format json \
  --db .local/audit/compliance.db
```

Supported scopes:

- `portfolio`: all repositories in the local ledger.
- `repository`: one repository, with `--repository owner/repo`.
- `audit_run`: one audit, with `--audit-run-id audit_...`.
- `merge_window`: merge events from the last `--days`, optionally with `--repository owner/repo`.

The report includes executive summary, repository coverage, merge/audit coverage, findings by priority, findings by standards control, critical/high remediation queue, recent improvements/regressions, pending unaudited merges, standards catalog versions, observed standards snapshot hashes, engine versions, generated time, and audit database path.

Reports read from local SQLite only. Generated reports should stay under ignored paths such as `.local/reports/` unless they have been reviewed for sharing.

## GitHub Repository Sync

Repository and merge sync commands need GitHub API access. You can either set a token:

```bash
export MCP_COMPLIANCE_SCAN_GITHUB_TOKEN=...
```

or authenticate the GitHub CLI:

```bash
gh auth login
```

If `MCP_COMPLIANCE_SCAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, and `GH_TOKEN` are absent, the CLI/MCP tries `gh auth token` and uses the local keychain-backed GitHub CLI credential.

## GitHub Actions

Copy `templates/github-actions/mcp-compliance-scan.yml` into each repository as:

```text
.github/workflows/mcp-compliance-scan.yml
```

The published template checks out `StoneyTECH/MCP-Compliance-Scan` directly and does not require a checkout token for public use. If you run a private mirror instead, add your own `token:` line that references a repository or organization secret with read access to that mirror.
