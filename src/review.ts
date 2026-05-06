import path from "node:path";
import { BASE_CHECKLIST, buildChecklist } from "./policy.js";
import { formatUntrustedTextBlock, sanitizeEvidenceText } from "./security.js";
import { StandardReference, formatStandardReference, referencesForRule } from "./standards.js";

export type ReviewProfile = "standard" | "strict" | "security";
export type Severity = "blocker" | "high" | "medium" | "low";
export type ReviewStatus = "pass" | "warn" | "fail";

export interface DiffLine {
  file: string;
  line: number;
  content: string;
}

export interface ParsedDiff {
  files: string[];
  addedLines: DiffLine[];
  rawBytes: number;
  truncated: boolean;
}

export interface ReviewFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: string;
  file?: string;
  line?: number;
  evidence: string;
  remediation: string;
  confidence: number;
  standards: StandardReference[];
}

export interface ReviewReport {
  tool: "mcp-compliance-scan";
  profile: ReviewProfile;
  status: ReviewStatus;
  summary: string;
  findingCount: number;
  counts: Record<Severity, number>;
  reviewedFiles: string[];
  findings: ReviewFinding[];
  checklist: string[];
  truncated: boolean;
}

export interface ReviewOptions {
  profile?: ReviewProfile;
  maxFindings?: number;
  language?: string;
  framework?: string;
  riskAreas?: string[];
  truncated?: boolean;
}

const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cs",
  ".css",
  ".go",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".mjs",
  ".php",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".sql",
  ".swift",
  ".ts",
  ".tsx",
  ".vue"
]);

const CONFIG_FILES = new Set([
  "package.json",
  "pyproject.toml",
  "requirements.txt",
  "Gemfile",
  "Dockerfile",
  "docker-compose.yml",
  "wrangler.toml"
]);

const TEST_PATTERNS = [
  /(^|\/)(__tests__|tests?|spec)\//i,
  /\.(test|spec)\.[cm]?[jt]sx?$/i,
  /_test\.go$/i,
  /test_.*\.py$/i
];

const LOCKFILES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "Cargo.lock",
  "poetry.lock",
  "uv.lock",
  "Gemfile.lock"
]);

export function parseUnifiedDiff(diffText: string, truncated = false): ParsedDiff {
  const files = new Set<string>();
  const addedLines: DiffLine[] = [];
  let currentFile: string | undefined;
  let newLine = 0;

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith("+++ ")) {
      const nextFile = rawLine.slice(4).trim();
      currentFile = normalizeDiffPath(nextFile);
      if (currentFile) {
        files.add(currentFile);
      }
      continue;
    }

    const hunkMatch = rawLine.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLine = Number.parseInt(hunkMatch[1] ?? "0", 10) - 1;
      continue;
    }

    if (!currentFile) {
      continue;
    }

    if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
      newLine += 1;
      addedLines.push({
        file: currentFile,
        line: newLine,
        content: rawLine.slice(1)
      });
      continue;
    }

    if (rawLine.startsWith(" ") || rawLine === "") {
      newLine += 1;
    }
  }

  return {
    files: [...files].sort(),
    addedLines,
    rawBytes: Buffer.byteLength(diffText, "utf8"),
    truncated
  };
}

export function reviewDiff(diffText: string, options: ReviewOptions = {}): ReviewReport {
  const profile = options.profile ?? "standard";
  const parsed = parseUnifiedDiff(diffText, options.truncated ?? false);
  const findings: ReviewFinding[] = [];

  for (const line of parsed.addedLines) {
    findings.push(...reviewAddedLine(line, profile));
  }

  findings.push(...reviewFileSet(parsed.files, profile, parsed.addedLines));

  const uniqueFindings = dedupeFindings(findings);
  const maxFindings = options.maxFindings ?? 50;
  const rankedFindings = uniqueFindings
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || b.confidence - a.confidence)
    .slice(0, maxFindings);

  const counts = countSeverities(rankedFindings);
  const status = counts.blocker > 0 || counts.high > 0 ? "fail" : rankedFindings.length > 0 ? "warn" : "pass";
  const checklist = buildChecklist({
    language: options.language,
    framework: options.framework,
    profile,
    riskAreas: options.riskAreas
  }).map((item) => {
    const standards = item.standards.map((standard) => `${standard.standardId}:${standard.control}`).join(", ");
    return `${item.required ? "required" : "recommended"}:${item.id} - ${item.prompt} [${standards}]`;
  });

  return {
    tool: "mcp-compliance-scan",
    profile,
    status,
    summary: summarize(status, counts, parsed.files.length, parsed.truncated),
    findingCount: rankedFindings.length,
    counts,
    reviewedFiles: parsed.files,
    findings: rankedFindings,
    checklist: checklist.length > 0 ? checklist : BASE_CHECKLIST.map((item) => item.prompt),
    truncated: parsed.truncated
  };
}

export function formatReviewMarkdown(report: ReviewReport): string {
  const lines = [
    `# Compliance Review`,
    ``,
    `Status: ${report.status.toUpperCase()}`,
    `Profile: ${report.profile}`,
    `Files reviewed: ${report.reviewedFiles.length}`,
    `Findings: ${report.findingCount} (${formatCounts(report.counts)})`,
    ``,
    report.summary
  ];

  if (report.truncated) {
    lines.push("", "Note: input was truncated before review, so results may be incomplete.");
  }

  if (report.findings.length === 0) {
    lines.push("", "No deterministic compliance findings were detected.");
  } else {
    lines.push("", "## Findings");
    for (const finding of report.findings) {
      const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "repository";
      lines.push(
        "",
        `### [${finding.severity}] ${finding.title}`,
        `- Rule: ${finding.ruleId}`,
        `- Category: ${finding.category}`,
        `- Standards: ${finding.standards.map(formatStandardReference).join("; ")}`,
        `- Location: ${location}`,
        "- Evidence:",
        ...formatUntrustedTextBlock(finding.evidence),
        `- Remediation: ${finding.remediation}`
      );
    }
  }

  lines.push("", "## Checklist");
  for (const item of report.checklist) {
    lines.push(`- ${item}`);
  }

  return `${lines.join("\n")}\n`;
}

function reviewAddedLine(line: DiffLine, profile: ReviewProfile): ReviewFinding[] {
  const findings: ReviewFinding[] = [];
  const content = line.content.trim();
  const fileName = path.basename(line.file);

  if (content.length === 0 || isGeneratedFile(line.file)) {
    return findings;
  }

  if (isScannerPatternLine(content)) {
    return findings;
  }

  if (hasPrivateKeyMaterial(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.private-key",
      title: "Private key material appears in the diff",
      severity: "blocker",
      category: "security",
      evidence: redactEvidence(content),
      remediation: "Remove the key material, rotate the credential, and load secrets from a managed secret store."
    }));
  }

  if (hasHardcodedSecret(content, line.file)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.hardcoded-secret",
      title: "Hardcoded secret-like value",
      severity: "blocker",
      category: "security",
      evidence: redactEvidence(content),
      remediation: "Move the value to a secret manager or environment variable and rotate it if it was real."
    }));
  }

  if (looksLikePromptInjection(content, line.file)) {
    findings.push(makeLineFinding(line, {
      ruleId: "mcp.prompt-injection",
      title: "Prompt-injection or tool-poisoning instruction added",
      severity: profile === "security" ? "high" : "medium",
      category: "mcp",
      evidence: redactEvidence(content),
      remediation: "Treat the text as untrusted data. Remove hidden or imperative model/tool instructions, or isolate them in tests with clear neutralization."
    }));
  }

  if (/\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']?0["']?/i.test(content) || /\brejectUnauthorized\s*:\s*false\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.tls-disabled",
      title: "TLS certificate verification is disabled",
      severity: "high",
      category: "security",
      evidence: content,
      remediation: "Keep TLS verification enabled and fix the certificate trust chain instead of bypassing it."
    }));
  }

  if (/(^|[^\w.])(eval|exec)\s*\(/.test(content) || /\bnew\s+Function\s*\(/.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.dynamic-execution",
      title: "Dynamic code execution added",
      severity: profile === "strict" || profile === "security" ? "high" : "medium",
      category: "security",
      evidence: content,
      remediation: "Replace dynamic execution with explicit parsing or dispatch. If unavoidable, validate and sandbox inputs."
    }));
  }

  if (/\bchild_process\.(exec|execSync)\s*\(/.test(content) || /\bshell\s*:\s*true\b/.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.command-execution",
      title: "Shell command execution added",
      severity: "high",
      category: "security",
      evidence: content,
      remediation: "Use execFile/spawn with argument arrays and validate any user-controlled values before execution."
    }));
  }

  if (looksLikeSqlConcatenation(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.sql-construction",
      title: "SQL appears to be constructed with interpolation or concatenation",
      severity: "high",
      category: "security",
      evidence: content,
      remediation: "Use parameterized queries or the ORM's binding API instead of string-built SQL."
    }));
  }

  if (/\b(skipAuth|disableAuth|bypassAuth|isAdmin\s*=\s*true|auth\s*:\s*false)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.auth-bypass",
      title: "Authentication or authorization bypass signal",
      severity: profile === "strict" || profile === "security" ? "high" : "medium",
      category: "security",
      evidence: content,
      remediation: "Keep auth checks enforced by default and isolate test bypasses behind non-production guards."
    }));
  }

  if (/(console\.\w+|logger\.\w+|log\.)\s*\(.*\b(password|passwd|token|secret|apiKey|ssn|dob|email)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "privacy.sensitive-logging",
      title: "Sensitive data may be logged",
      severity: profile === "security" ? "high" : "medium",
      category: "privacy",
      evidence: redactEvidence(content),
      remediation: "Remove sensitive fields from logs or log stable non-sensitive identifiers."
    }));
  }

  if (/\bdangerouslySetInnerHTML\s*=|\.innerHTML\s*=|\bdocument\.write\s*\(/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.dom-sink",
      title: "Unsafe browser rendering sink added",
      severity: "medium",
      category: "security",
      evidence: content,
      remediation: "Render trusted structured data, sanitize HTML with an approved sanitizer, or avoid direct HTML sinks."
    }));
  }

  if (/\bfetch\s*\(/.test(content) && !/\b(signal|AbortSignal|timeout)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "reliability.fetch-timeout",
      title: "Outbound fetch does not show timeout or cancellation",
      severity: "low",
      category: "reliability",
      evidence: content,
      remediation: "Pass an AbortSignal or the project-standard timeout wrapper so callers cannot hang indefinitely."
    }));
  }

  if (/(\/\/|#|\/\*|\*)\s*(TODO|FIXME)\b/i.test(content) && /\b(security|auth|permission|encrypt|privacy|token|password)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "process.security-todo",
      title: "Security-sensitive TODO added",
      severity: profile === "strict" ? "medium" : "low",
      category: "process",
      evidence: content,
      remediation: "Resolve the security-sensitive TODO before merge or link it to a tracked blocking follow-up."
    }));
  }

  if (/(@ts-ignore|@ts-expect-error|eslint-disable|type:\s*ignore|noqa)/i.test(content) && !/\b(reason|because|safe|intentional)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "quality.unexplained-suppression",
      title: "Lint or type suppression lacks an explanation",
      severity: "low",
      category: "quality",
      evidence: content,
      remediation: "Add the reason for the suppression or remove the suppression by fixing the underlying issue."
    }));
  }

  if (fileName === "package.json" && /"[^"]+"\s*:\s*"(latest|\*|x)"/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "supply-chain.unpinned-dependency",
      title: "Dependency version is not pinned enough for review",
      severity: "medium",
      category: "supply-chain",
      evidence: content,
      remediation: "Pin dependency versions or use the repository's approved version range policy."
    }));
  }

  if (/\b(debug\s*=\s*true|DEBUG\s*:\s*true|app\.debug\s*=\s*true)\b/i.test(content)) {
    findings.push(makeLineFinding(line, {
      ruleId: "security.debug-enabled",
      title: "Debug mode appears enabled",
      severity: "medium",
      category: "security",
      evidence: content,
      remediation: "Ensure debug mode cannot be enabled in production and gate it through environment-specific config."
    }));
  }

  return findings;
}

function reviewFileSet(files: string[], profile: ReviewProfile, addedLines: DiffLine[]): ReviewFinding[] {
  const findings: ReviewFinding[] = [];
  const changedCode = files.filter((file) => isSourceLike(file) && !isTestFile(file));
  const changedTests = files.filter(isTestFile);
  const packageChanged = files.some((file) => path.basename(file) === "package.json");
  const packageDependencyChanged = addedLines.some((line) => {
    const content = line.content.trim();
    return path.basename(line.file) === "package.json"
      && (
        /^"(dependencies|devDependencies|optionalDependencies|peerDependencies)"\s*:/.test(content)
        || /^"[^"]+"\s*:\s*"(?:[\^~]?\d+\.\d+\.\d+|latest|\*|x)"/i.test(content)
      );
  });
  const lockfileChanged = files.some((file) => LOCKFILES.has(path.basename(file)));
  const migrationChanged = files.some((file) => /(^|\/)(migrations?|schema|prisma)\//i.test(file) || /migration/i.test(file));

  if (changedCode.length > 0 && changedTests.length === 0) {
    findings.push({
      ruleId: "quality.missing-tests",
      title: "Code changed without accompanying tests",
      severity: profile === "strict" ? "medium" : "low",
      category: "quality",
      evidence: `Changed code files: ${changedCode.slice(0, 6).join(", ")}${changedCode.length > 6 ? " ..." : ""}`,
      remediation: "Add focused tests for the changed behavior or document why tests are not applicable.",
      confidence: 0.68,
      standards: referencesForRule("quality.missing-tests")
    });
  }

  if (packageChanged && packageDependencyChanged && !lockfileChanged) {
    findings.push({
      ruleId: "supply-chain.lockfile-drift",
      title: "Package manifest changed without a lockfile update",
      severity: "medium",
      category: "supply-chain",
      evidence: "package.json changed but no recognized lockfile changed.",
      remediation: "Update the matching lockfile or explain why this package is intentionally lockfile-free.",
      confidence: 0.74,
      standards: referencesForRule("supply-chain.lockfile-drift")
    });
  }

  if (migrationChanged && !files.some((file) => /rollback|down|revert/i.test(file))) {
    findings.push({
      ruleId: "data.migration-rollback",
      title: "Migration or schema change may need rollback review",
      severity: "low",
      category: "data",
      evidence: `Migration/schema files changed: ${files.filter((file) => /migration|schema|prisma/i.test(file)).slice(0, 6).join(", ")}`,
      remediation: "Confirm rollout, rollback, and backward compatibility before merge.",
      confidence: 0.55,
      standards: referencesForRule("data.migration-rollback")
    });
  }

  return findings;
}

function makeLineFinding(
  line: DiffLine,
  partial: Omit<ReviewFinding, "file" | "line" | "confidence" | "standards"> & { confidence?: number; standards?: StandardReference[] }
): ReviewFinding {
  return {
    ...partial,
    file: line.file,
    line: line.line,
    confidence: partial.confidence ?? 0.8,
    standards: partial.standards ?? referencesForRule(partial.ruleId)
  };
}

function normalizeDiffPath(diffPath: string): string | undefined {
  if (diffPath === "/dev/null") {
    return undefined;
  }

  const clean = diffPath.replace(/^"|"$/g, "");
  if (clean.startsWith("a/") || clean.startsWith("b/")) {
    return clean.slice(2);
  }

  return clean;
}

function isSourceLike(file: string): boolean {
  const base = path.basename(file);
  const ext = path.extname(file);
  return SOURCE_EXTENSIONS.has(ext) || CONFIG_FILES.has(base);
}

function isTestFile(file: string): boolean {
  return TEST_PATTERNS.some((pattern) => pattern.test(file));
}

function isGeneratedFile(file: string): boolean {
  return /(^|\/)(dist|build|coverage|vendor|generated)\//i.test(file) || /\.min\.[cm]?js$/i.test(file);
}

function hasPrivateKeyMaterial(content: string): boolean {
  return /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/.test(content);
}

function hasHardcodedSecret(content: string, file: string): boolean {
  if (/\.md$/i.test(file) || /\.snap$/i.test(file)) {
    return false;
  }

  if (content.includes("${")) {
    return false;
  }

  if (/\b(process\.env|import\.meta\.env|Deno\.env|os\.environ|getenv|secretRef|fromSecret)\b/.test(content)) {
    return false;
  }

  if (/\b(example|sample|dummy|placeholder|changeme|redacted|xxxx|test-token|not-a-secret)\b/i.test(content)) {
    return false;
  }

  return /\b(api[_-]?key|client[_-]?secret|secret|access[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key)\b\s*[:=]\s*["'`][^"'`]{8,}["'`]/i.test(content);
}

function looksLikePromptInjection(content: string, file: string): boolean {
  if (!isPromptInjectionReviewPath(file)) {
    return false;
  }

  const normalized = content.replace(/\s+/g, " ").trim();
  return /(ignore|disregard|override|forget).{0,80}(previous|prior|above|system|developer|instruction|policy)/i.test(normalized)
    || /(system prompt|developer message|hidden instruction|jailbreak).{0,80}(ignore|override|secret|token|tool|policy)/i.test(normalized)
    || /\b(call|invoke|use)\b.{0,40}\b(tool|mcp tool|function)\b.{0,80}\b(secret|token|credential|private key|filesystem|shell)\b/i.test(normalized)
    || /\b(exfiltrate|leak|send|post)\b.{0,80}\b(secret|token|credential|private key|environment variable)\b/i.test(normalized)
    || /<!--.*\b(ignore|system prompt|developer message|tool call|exfiltrate)\b.*-->/i.test(normalized);
}

function isPromptInjectionReviewPath(file: string): boolean {
  const base = path.basename(file).toLowerCase();
  const ext = path.extname(file).toLowerCase();
  return [".md", ".mdx", ".txt", ".html", ".json", ".yaml", ".yml", ".toml"].includes(ext)
    || ["system.md", "prompt.md", "instructions.md", "mcp.json", "package.json"].includes(base)
    || /(^|\/)(prompts?|instructions?|docs?|\.github)\//i.test(file);
}

function looksLikeSqlConcatenation(content: string): boolean {
  const hasSql = /\b(SELECT|INSERT|UPDATE|DELETE|UPSERT|ALTER|DROP)\b/i.test(content);
  const hasInterpolation = /(`[^`]*\$\{[^}]+}[^`]*`|\+\s*\w+|\w+\s*\+)/.test(content);
  const queryCall = /\b(query|execute|exec|raw|prepare)\s*\(/i.test(content);
  return hasSql && hasInterpolation && (queryCall || /sql/i.test(content));
}

function isScannerPatternLine(content: string): boolean {
  return /^if\s*\(\//.test(content) || /^return\s+\//.test(content) || content.includes(".test(content)");
}

function redactEvidence(content: string): string {
  return sanitizeEvidenceText(content
    .replace(/((?:api[_-]?key|client[_-]?secret|secret|access[_-]?token|refresh[_-]?token|password|passwd|private[_-]?key)\b\s*[:=]\s*["'`])([^"'`]{4,})(["'`])/gi, "$1***redacted***$3")
    .replace(/-----BEGIN ([A-Z ]+PRIVATE KEY)-----.*$/i, "-----BEGIN $1----- ***redacted***"));
}

function dedupeFindings(findings: ReviewFinding[]): ReviewFinding[] {
  const seen = new Set<string>();
  const result: ReviewFinding[] = [];

  for (const finding of findings) {
    const key = [finding.ruleId, finding.file ?? "", finding.line ?? "", finding.title].join("|");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(finding);
  }

  return result;
}

function severityWeight(severity: Severity): number {
  switch (severity) {
    case "blocker":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
  }
}

function countSeverities(findings: ReviewFinding[]): Record<Severity, number> {
  return findings.reduce<Record<Severity, number>>(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { blocker: 0, high: 0, medium: 0, low: 0 }
  );
}

function formatCounts(counts: Record<Severity, number>): string {
  return `blocker ${counts.blocker}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}`;
}

function summarize(status: ReviewStatus, counts: Record<Severity, number>, fileCount: number, truncated: boolean): string {
  if (status === "pass") {
    return `Reviewed ${fileCount} changed file(s); no deterministic policy issues were detected.`;
  }

  const prefix = status === "fail" ? "Merge-blocking issues detected" : "Review attention recommended";
  const suffix = truncated ? " Input was truncated, so run again with a larger diff limit for full coverage." : "";
  return `${prefix}: ${formatCounts(counts)} across ${fileCount} changed file(s).${suffix}`;
}
