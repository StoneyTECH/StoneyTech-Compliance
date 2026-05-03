import { StandardReference, referencesForChecklistItem } from "./standards.js";

export const POLICY_URI = "compliance://policy/code-review";

export const POLICY_TEXT = `# Code Review Policy

The compliance review should focus on concrete, user-impacting risk. Findings must be actionable, tied to a file and line when possible, ranked by severity, and mapped to a recognized standard where possible.

## Standards Baseline

- OWASP ASVS 5.0.0 is the primary application, API, web, OAuth/OIDC, logging, data protection, and secure communication baseline.
- OWASP API Security Top 10 2023 is the API prioritization baseline.
- OWASP Top 10 2025 is the web application awareness baseline.
- NIST SSDF SP 800-218 v1.1 is the secure development process baseline.
- MITRE CWE Top 25 2025 supplies weakness identifiers for code-level findings.
- OpenSSF SLSA and Scorecard supply supply-chain and repository posture controls.
- IETF RFC 9700 supplies OAuth security best current practice.
- Model Context Protocol authorization and security guidance supply MCP-specific requirements.

## Required Review Gates

- No secrets, private keys, credentials, tokens, or production endpoints are introduced in code, tests, logs, fixtures, or configuration.
- Authentication, authorization, and tenant boundaries are not weakened or bypassed.
- User-controlled input is validated before it reaches SQL, shell commands, file paths, templates, redirects, or dynamic code execution.
- Sensitive data is not logged, returned to clients, committed to fixtures, or exposed in error messages.
- Network calls have timeout, retry, and failure behavior that is appropriate for the caller.
- Dependency changes are pinned intentionally and do not use \`latest\`, \`*\`, or unreviewed broad ranges in deployable code.
- Behavior changes include tests or an explicit justification for why tests are not applicable.
- Migrations, schema changes, and destructive operations include rollback or compatibility considerations.

## Finding Severity

- \`blocker\`: likely credential exposure, auth bypass, destructive data loss, or exploitable remote code execution.
- \`high\`: security, privacy, data integrity, or availability risk that should block merge until fixed.
- \`medium\`: correctness, maintainability, observability, test, or reliability issue that deserves attention before merge.
- \`low\`: review note, hardening suggestion, or policy hygiene issue.

## Review Style

Reviews should be concise and evidence-driven. Prefer one finding per concrete issue, include a remediation path, and avoid speculative comments when the diff does not provide enough evidence.
`;

export interface ChecklistItem {
  id: string;
  category: string;
  prompt: string;
  required: boolean;
  standards: StandardReference[];
}

export const BASE_CHECKLIST: ChecklistItem[] = [
  checklistItem("secrets", "security", "Check that no secrets, keys, tokens, passwords, or private key material were added.", true),
  checklistItem("auth-boundaries", "security", "Verify authentication, authorization, role checks, and tenant boundaries are preserved.", true),
  checklistItem("input-validation", "security", "Trace user-controlled input into SQL, shell, file paths, templates, redirects, and dynamic code execution.", true),
  checklistItem("sensitive-logging", "privacy", "Confirm sensitive data is not logged, exposed in errors, or committed in fixtures.", true),
  checklistItem("network-resilience", "reliability", "Check outbound calls for timeout, retry, cancellation, and failure behavior.", false),
  checklistItem("dependency-hygiene", "supply-chain", "Review dependency changes for broad ranges, unpinned versions, lockfile drift, and unexpected packages.", true),
  checklistItem("tests", "quality", "Confirm behavior changes have tests or a clear reason tests are not applicable.", true),
  checklistItem("migration-safety", "data", "For schema or migration changes, verify rollout, rollback, and backward compatibility.", false)
];

export function buildChecklist(options: {
  language?: string;
  framework?: string;
  profile?: string;
  riskAreas?: string[];
} = {}): ChecklistItem[] {
  const items = [...BASE_CHECKLIST];
  const language = options.language?.toLowerCase() ?? "";
  const framework = options.framework?.toLowerCase() ?? "";
  const riskAreas = new Set(options.riskAreas?.map((area) => area.toLowerCase()) ?? []);

  if (["typescript", "javascript", "node", "react"].some((needle) => language.includes(needle) || framework.includes(needle))) {
    items.push(
      checklistItem("browser-sinks", "security", "Inspect DOM sinks such as innerHTML, dangerouslySetInnerHTML, postMessage, and URL construction.", true),
      checklistItem("node-process", "security", "Check child_process, fs path joins, environment handling, and server-side request handling.", true)
    );
  }

  if (["python", "django", "flask", "fastapi"].some((needle) => language.includes(needle) || framework.includes(needle))) {
    items.push(
      checklistItem("python-exec", "security", "Inspect eval, exec, pickle, yaml loading, subprocess, and path handling.", true),
      checklistItem("python-web", "security", "Check request validation, serializer boundaries, ORM query construction, and debug settings.", true)
    );
  }

  if (options.profile === "security" || riskAreas.has("security")) {
    items.push(checklistItem("abuse-cases", "security", "Consider abuse cases: privilege escalation, replay, rate limits, SSRF, injection, and account enumeration.", true));
  }

  if (riskAreas.has("mcp")) {
    items.push(
      checklistItem("mcp-authorization", "mcp", "For remote MCP servers, verify OAuth discovery, least-privilege scopes, token audience validation, and no token passthrough.", true),
      checklistItem("mcp-tool-safety", "mcp", "Review tool descriptions, inputs, file/network/command access, consent boundaries, and confused-deputy paths.", true)
    );
  }

  if (riskAreas.has("oauth")) {
    items.push(
      checklistItem("oauth-redirects", "oauth", "Verify exact redirect URI matching, no open redirectors, state/PKCE protections, and removal of deprecated flows.", true),
      checklistItem("oauth-token-validation", "oauth", "Check token audience, issuer, type, expiry, scope, sender constraints, storage, and logging behavior.", true)
    );
  }

  if (riskAreas.has("api")) {
    items.push(
      checklistItem("api-rate-limits", "api", "Verify API endpoints enforce resource limits, pagination bounds, rate limits, and predictable failure behavior.", true),
      checklistItem("api-inventory", "api", "Check that new or changed API routes are inventoried, versioned, authenticated, and documented.", false)
    );
  }

  if (riskAreas.has("compliance") || riskAreas.has("privacy")) {
    items.push(checklistItem("data-minimization", "privacy", "Check that collected, stored, and emitted personal data is minimized and justified.", true));
  }

  return items;
}

function checklistItem(id: string, category: string, prompt: string, required: boolean): ChecklistItem {
  return {
    id,
    category,
    prompt,
    required,
    standards: referencesForChecklistItem(id)
  };
}
