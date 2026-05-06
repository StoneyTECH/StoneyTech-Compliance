# StoneyTECH-MCP-Compliance-Scan

Agent-first pattern repo for **deterministic code-review compliance checks**.

This repo demonstrates one reusable shape:

- one diff, repository, or merge event comes in
- deterministic review rules inspect it
- findings map to named standards and controls
- local audit history and priority order stay queryable

The point is not one team's current policy pack. The point is the pattern.

Companion reading:

- [StoneyTECH site](https://stoneytech.net)
- [StoneyTECH MCP page](https://stoneytech.net/mcp)
- [StoneyTECH public content MCP](https://public-content-mcp.stoneytech.net/mcp)

See also:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [AXIOMS.md](AXIOMS.md)

## Purpose

Use this repo as a reference when an agent or local operator needs:

- deterministic compliance checks before merge or publication
- standards-mapped findings instead of floating review opinion
- local audit history, merge tracking, and remediation ordering
- a narrow MCP surface for code-review compliance work

Do not use this repo as a remote trust oracle or a substitute for your full runtime governance system. It is a local-first pattern repo and tool surface, not a complete operating platform.

## Pattern claim

**Review before promotion. Name the rule, cite the standard, keep the evidence local, and keep the output reproducible.**

That shape is useful for:

- pull-request review gates
- merge-event auditing
- local historical compliance ledgers
- deterministic remediation ordering
- MCP-safe code review workflows

## Design contract

### Graph first

The control shape is:

```text
diff or merge event -> deterministic review -> standards mapping -> audit ledger -> remediation order
```

Even when a CLI command runs the flow, the review graph is named first so agents can reuse the shape inside larger systems.

### MCP first

The bounded context surface is:

- one diff, repository path, or merge event
- one policy and standards mapping layer
- one local audit ledger
- one deterministic review result

If this pattern is wrapped by an MCP later, that MCP should expose the narrow compliance-review surface, not an open-ended shell or deployment runtime.

### Template first

The reusable contracts are:

- deterministic finding schema
- standards-control mapping
- priority band and remediation ordering
- local audit report shape

Those contracts are the portable part. A different team can swap policy details without losing the pattern.

## Axioms Addressed

- [Axiom #2 — Push work down toward determinism](https://stoneytech.net/axioms#push-toward-determinism): the scanner turns review judgment into deterministic rules, policy mappings, and reproducible outputs.
- [Axiom #4 — GVR before pasting](https://stoneytech.net/axioms#gvr-before-pasting): review happens before merge or publication, not after hand-wavy confidence.
- [Axiom #5 — Never trust 'running' without sentinels](https://stoneytech.net/axioms#never-trust-running-without-sentinels): audit history, merge tracking, and standards monitoring create evidence instead of green-light theater.
- [Axiom #11 — Cite or be silent](https://stoneytech.net/axioms#cite-or-be-silent): findings map to named standards and controls instead of floating opinion.
- [Axiom #13 — Ship with the failure mode named](https://stoneytech.net/axioms#ship-with-the-failure-mode-named): the tool names risk classes directly: secrets, injection, auth drift, unsafe MCP boundaries, and review-policy gaps.
- [Axiom #16 — Don't comment without building. Don't curate without proving.](https://stoneytech.net/axioms#curate-and-prove): the standards catalog, rule pack, tests, and audit schema are working proof, not a reading list.
- [Axiom #17 — Threat-model the surface](https://stoneytech.net/axioms#threat-model-the-surface): MCP roots, git refs, token handling, and prompt-injection review are treated as adversarial surfaces.
- [Axiom #21 — Scope before sharing](https://stoneytech.net/axioms#scope-before-sharing): public code ships; private audit ledgers, runtime state, credentials, and repository findings stay local.

See [AXIOMS.md](AXIOMS.md) for the local doctrine map.

## Related MCPs

- StoneyTECH public content MCP: [https://public-content-mcp.stoneytech.net/mcp](https://public-content-mcp.stoneytech.net/mcp)
- local compliance MCP surface: `mcp-compliance-scan-mcp`

The shared StoneyTECH MCP gives doctrine and public context. This repo gives the local compliance-review surface itself.

## Agent Read First

If an IDE agent opens this repo, read it in this order:

1. [README.md](README.md)
   - purpose, pattern claim, runtime shape, and boundaries
2. [AXIOMS.md](AXIOMS.md)
   - immutable StoneyTECH doctrine this repo serves
3. [policies/code-review.md](policies/code-review.md)
   - local review rules and public-safe review posture
4. [policies/standards-catalog.md](policies/standards-catalog.md)
   - standards sources and control families
5. [schema/audit-ledger.sql](schema/audit-ledger.sql)
   - local audit graph and persistence contract
6. [src/index.ts](src/index.ts)
   - MCP tool surface
7. [src/cli.ts](src/cli.ts)
   - operator-facing CLI contract
8. [src/review.ts](src/review.ts)
   - deterministic finding logic
9. [src/priority.ts](src/priority.ts)
   - remediation ordering and dependency-aware prioritization
10. [docs/public-repo-local-data.md](docs/public-repo-local-data.md)
   - what stays public and what stays local

That sequence is the gold mine: doctrine, policy, schema, tool surface, review engine, priority engine, and local-data boundary.

## Runtime shape

```text
local diff or repository
  -> deterministic review rules
  -> standards/control mapping
  -> optional local audit ledger write
  -> priority order and remediation plan
```

## When to use this pattern

Use this pattern when:

- deterministic review is more important than generative commentary
- findings must cite controls or standards
- local audit history matters
- the MCP surface should stay narrow and inspectable

Do not use this pattern when:

- the workflow needs broad remote orchestration first
- the tool should own your full governance platform
- private runtime state should be exposed through the same interface

## Standalone scenario

Use `StoneyTECH-MCP-Compliance-Scan` by itself for:

- local review of a diff before commit or merge
- deterministic merge-event auditing
- standards-aware remediation planning
- local historical audit ledgers for one team or repository set

## Pair scenarios

### With the StoneyTECH public content MCP

Use the pair when:

- an IDE agent needs doctrine from the public site
- then needs deterministic compliance review locally

Flow:

```text
StoneyTECH public content MCP -> StoneyTECH-MCP-Compliance-Scan
```

The public MCP gives axioms, essays, and public framing. This repo gives deterministic local review and audit surfaces.

### With a local scheduler such as n8n

Use the pair when:

- review or standards checks need scheduled polling
- merge events should be routed into local audits automatically

Flow:

```text
local scheduler -> StoneyTECH-MCP-Compliance-Scan
```

The scheduler handles cadence and notification. This repo remains the policy and review engine.

## Bring your own runtime

This repo is meant to be adopted by outside teams and outside agents.

Start with:

- local stdio MCP
- local CLI
- local SQLite audit ledger
- local scheduler templates

Grow later into:

- organization policy overlays
- remote transport with proper authorization
- richer merge-event pipelines
- external dashboards built from local report exports
- larger workflow orchestration around the same deterministic core

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
