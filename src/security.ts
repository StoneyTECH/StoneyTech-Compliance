import path from "node:path";
import { fileURLToPath } from "node:url";

export type ToolEffect = "local-read" | "local-write" | "network" | "repo-clone" | "untrusted-input";

export interface McpToolSecurityPolicy {
  tool: string;
  effects: ToolEffect[];
  defaultDecision: "allow" | "validate";
  guardrails: string[];
}

export const MCP_TOOL_SECURITY_POLICIES: Record<string, McpToolSecurityPolicy> = {
  standards_catalog: policy("standards_catalog", ["local-read"], ["Reads the built-in standards catalog only."]),
  review_diff: policy("review_diff", ["untrusted-input"], ["Treats supplied diff text as untrusted content.", "Markdown output labels evidence as untrusted repository content."]),
  review_repository: policy("review_repository", ["local-read"], ["Requires repoPath to be inside allowed roots.", "Validates optional git refs before invoking git."]),
  init_audit_db: policy("init_audit_db", ["local-write"], ["Requires dbPath to be inside allowed roots when provided."]),
  review_repository_and_persist: policy("review_repository_and_persist", ["local-read", "local-write"], ["Requires repoPath and dbPath to be inside allowed roots.", "Validates optional git refs before invoking git."]),
  audit_history: policy("audit_history", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  get_audit_run: policy("get_audit_run", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  audit_trends: policy("audit_trends", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  prioritize_audit_run: policy("prioritize_audit_run", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  remediation_plan: policy("remediation_plan", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  repository_impact_graph: policy("repository_impact_graph", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  sync_github_repositories: policy("sync_github_repositories", ["network", "local-write"], ["Uses local environment or gh CLI token discovery.", "Requires dbPath to be inside allowed roots when provided."]),
  list_registered_repositories: policy("list_registered_repositories", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  sync_repository_merges: policy("sync_repository_merges", ["network", "local-write"], ["Requires dbPath to be inside allowed roots when provided.", "Validates branch names before GitHub polling."]),
  audit_merge: policy("audit_merge", ["local-read", "local-write", "network", "repo-clone"], ["Requires repoPath, checkoutRoot, and dbPath to be inside allowed roots when provided.", "Uses persisted merge metadata rather than free-form commands."]),
  audit_unprocessed_merges: policy("audit_unprocessed_merges", ["local-read", "local-write", "network", "repo-clone"], ["Requires checkoutRoot and dbPath to be inside allowed roots when provided."]),
  merge_audit_history: policy("merge_audit_history", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  get_merge_audit: policy("get_merge_audit", ["local-read"], ["Requires dbPath to be inside allowed roots when provided."]),
  compliance_report: policy("compliance_report", ["local-read"], ["Requires dbPath to be inside allowed roots when provided.", "Limits queue-style report sections by caller-supplied row limit."]),
  compliance_checklist: policy("compliance_checklist", ["local-read"], ["Reads built-in checklist and standards mappings only."]),
  mcp_security_policy: policy("mcp_security_policy", ["local-read"], ["Reports configured roots and per-tool security effects."])
};

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const SAFE_GIT_REF = /^[A-Za-z0-9._/@:+~^-]+$/;

export function securityPolicyPayload(): {
  roots: {
    allowAnyRoot: boolean;
    allowedRoots: string[];
    source: string;
  };
  tools: McpToolSecurityPolicy[];
} {
  return {
    roots: {
      allowAnyRoot: allowAnyRoot(),
      allowedRoots: allowedRoots(),
      source: configuredAllowedRoots() ? "environment" : "default"
    },
    tools: Object.values(MCP_TOOL_SECURITY_POLICIES).sort((left, right) => left.tool.localeCompare(right.tool))
  };
}

export function formatSecurityPolicyMarkdown(): string {
  const payload = securityPolicyPayload();
  const lines = [
    "# MCP Security Policy",
    "",
    `Allow any root: ${payload.roots.allowAnyRoot ? "yes" : "no"}`,
    `Root source: ${payload.roots.source}`,
    "",
    "## Allowed Roots",
    "",
    ...(
      payload.roots.allowAnyRoot
        ? ["- any local path is allowed by explicit environment override"]
        : payload.roots.allowedRoots.map((root) => `- ${root}`)
    ),
    "",
    "## Tool Effects",
    "",
    "| Tool | Effects | Decision | Guardrails |",
    "| --- | --- | --- | --- |"
  ];

  for (const tool of payload.tools) {
    lines.push(`| ${tool.tool} | ${tool.effects.join(", ")} | ${tool.defaultDecision} | ${tool.guardrails.join("<br>")} |`);
  }

  return `${lines.join("\n")}\n`;
}

export function assertMcpPathAllowed(input: string | undefined, label: string): string | undefined {
  if (!input) {
    return undefined;
  }

  const resolved = path.resolve(input);
  if (allowAnyRoot()) {
    return resolved;
  }

  const roots = allowedRoots();
  if (roots.some((root) => isPathInside(resolved, root))) {
    return resolved;
  }

  throw new Error(`${label} is outside the configured MCP allowed roots: ${resolved}. Set MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS to a ${path.delimiter}-separated allowlist, or set MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT=1 for an explicit local-only override.`);
}

export function assertSafeGitRef(ref: string | undefined, label: string): void {
  if (!ref) {
    return;
  }

  if (
    ref.length > 200
    || ref.startsWith("-")
    || ref.includes("..")
    || /[\s\0]/.test(ref)
    || !SAFE_GIT_REF.test(ref)
  ) {
    throw new Error(`${label} is not an allowed git ref: ${ref}`);
  }
}

export function sanitizeEvidenceText(value: string, maxLength = 1000): string {
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .slice(0, maxLength);
}

export function formatUntrustedTextBlock(value: string): string[] {
  return [
    "Untrusted repository content:",
    "",
    "```text",
    sanitizeEvidenceText(value).replace(/```/g, "` ` `"),
    "```"
  ];
}

function policy(tool: string, effects: ToolEffect[], guardrails: string[]): McpToolSecurityPolicy {
  return {
    tool,
    effects,
    defaultDecision: effects.some((effect) => effect === "local-write" || effect === "network" || effect === "repo-clone") ? "validate" : "allow",
    guardrails
  };
}

function allowedRoots(): string[] {
  const configured = configuredAllowedRoots()
    ?.split(path.delimiter)
    .map((item) => item.trim())
    .filter(Boolean);
  const roots = configured && configured.length > 0
    ? configured
    : [process.cwd(), PACKAGE_ROOT, path.join(PACKAGE_ROOT, ".local")];
  return [...new Set(roots.map((root) => path.resolve(root)))];
}

function allowAnyRoot(): boolean {
  return TRUE_VALUES.has(String(process.env.MCP_COMPLIANCE_SCAN_ALLOW_ANY_ROOT ?? "").toLowerCase());
}

function configuredAllowedRoots(): string | undefined {
  return process.env.MCP_COMPLIANCE_SCAN_ALLOWED_ROOTS;
}

function isPathInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
