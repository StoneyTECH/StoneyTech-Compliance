# Standards Monitoring

The first automation layer is intentionally boring: run the local standards checker, parse JSON, and notify only when upstream standards move or the checker cannot verify a source.

## Local Commands

```bash
npm run check:standards
npm run check:standards:json
```

`check:standards` prints Markdown and exits nonzero on updates or errors.

`check:standards:json` prints a stable JSON payload and never fails. This is the preferred mode for n8n because the workflow can decide how to route updates.

## JSON Contract

```json
{
  "checkedAt": "2026-05-03T00:00:00.000Z",
  "summary": {
    "total": 11,
    "okCount": 7,
    "updateCount": 0,
    "trackingCount": 4,
    "errorCount": 0
  },
  "results": [
    {
      "standardId": "owasp-asvs-5.0.0",
      "name": "Application Security Verification Standard",
      "authority": "OWASP",
      "currentVersion": "5.0.0",
      "latestVersion": "5.0.0",
      "sourceUrl": "https://raw.githubusercontent.com/OWASP/ASVS/master/README.md",
      "status": "ok"
    }
  ]
}
```

Statuses:

- `ok`: catalog version matches the upstream version marker.
- `update_available`: upstream version differs from the catalog.
- `tracking`: source is rolling or unversioned; reachability and an expected marker were verified.
- `error`: source could not be reached or parsed.

## n8n Workflow Shape

1. Cron trigger weekly.
2. Execute command locally or import `workflows/n8n/standards-monitor.template.json`.

   ```bash
   cd /path/to/MCP-Compliance-Scan && npm run check:standards:json
   ```

3. Parse JSON from stdout.
4. IF `summary.updateCount > 0 || summary.errorCount > 0`.
5. Notify Slack/email and include each result where `status !== "ok" && status !== "tracking"`.
6. Optional next step: create a GitHub issue or draft PR that updates `src/standards.ts` and `policies/standards-catalog.md`.

Later, this can move from `Execute Command` to an HTTP or MCP call, but keeping the version-detection logic in the repo prevents n8n from becoming the source of truth.

The n8n workflow template can live in GitHub because it has no credentials. The actual n8n instance, credentials, executions, and local SQLite data should stay in ignored local paths. See `docs/public-repo-local-data.md`.

For repository audits, n8n should prefer the merge-event flow: call `sync_github_repositories`, `sync_repository_merges`, then `audit_unprocessed_merges`. Follow-up routing can call `prioritize_audit_run`, `remediation_plan`, `repository_impact_graph`, or `merge_audit_history` for deterministic fix ordering and standards-control graph output. That keeps the audit ledger deterministic and leaves n8n as scheduler/notifier only.
