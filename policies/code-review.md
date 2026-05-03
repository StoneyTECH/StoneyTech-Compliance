# Code Review Policy

The compliance review should focus on concrete, user-impacting risk. Findings must be actionable, tied to a file and line when possible, and ranked by severity.

## Required Review Gates

- No secrets, private keys, credentials, tokens, or production endpoints are introduced in code, tests, logs, fixtures, or configuration.
- Authentication, authorization, and tenant boundaries are not weakened or bypassed.
- User-controlled input is validated before it reaches SQL, shell commands, file paths, templates, redirects, or dynamic code execution.
- Sensitive data is not logged, returned to clients, committed to fixtures, or exposed in error messages.
- Network calls have timeout, retry, and failure behavior that is appropriate for the caller.
- Dependency changes are pinned intentionally and do not use `latest`, `*`, or unreviewed broad ranges in deployable code.
- Behavior changes include tests or an explicit justification for why tests are not applicable.
- Migrations, schema changes, and destructive operations include rollback or compatibility considerations.

## Finding Severity

- `blocker`: likely credential exposure, auth bypass, destructive data loss, or exploitable remote code execution.
- `high`: security, privacy, data integrity, or availability risk that should block merge until fixed.
- `medium`: correctness, maintainability, observability, test, or reliability issue that deserves attention before merge.
- `low`: review note, hardening suggestion, or policy hygiene issue.

## Review Style

Reviews should be concise and evidence-driven. Prefer one finding per concrete issue, include a remediation path, and avoid speculative comments when the diff does not provide enough evidence.
