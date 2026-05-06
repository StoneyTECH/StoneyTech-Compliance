#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  formatAuditHistoryMarkdown,
  formatAuditTrendsMarkdown,
  initAuditDatabase,
  listAuditRuns,
  persistAuditRun,
  summarizeAuditTrends
} from "./audit.js";
import {
  getRepositoryDiff,
  getRepositoryExactDiff,
  ReviewMode
} from "./git.js";
import {
  auditMergeEvent,
  auditUnprocessedMerges,
  formatMergeHistoryMarkdown,
  formatRepositoryListMarkdown,
  listRegisteredRepositories,
  mergeAuditHistory,
  syncGithubRepositories,
  syncRepositoryMerges
} from "./merge.js";
import {
  formatPriorityPlanMarkdown,
  prioritizeFindings,
  PriorityBand
} from "./priority.js";
import {
  ComplianceReportScope,
  formatComplianceReportMarkdown,
  generateComplianceReport
} from "./report.js";
import {
  formatReviewMarkdown,
  reviewDiff,
  ReviewProfile
} from "./review.js";
import {
  STANDARDS_CATALOG,
  formatStandardsCatalogMarkdown
} from "./standards.js";

type OutputFormat = "markdown" | "json" | "github";
type ReportOutputFormat = "markdown" | "json";
type FailBand = PriorityBand | "none";

interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

const BAND_ORDER: Record<PriorityBand, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const HELP = `Compliance CLI

Usage:
  mcp-compliance-scan <command> [options]

Commands:
  review                     Review a repository diff for local/CI use.
  audit-merge                Review an exact base..target merge diff.
  init-db                    Initialize the local SQLite audit ledger.
  history                    List recent audit runs.
  trends                     Summarize local audit trends.
  standards                  Print the standards catalog.
  sync-github-repos          Inventory GitHub repositories into local SQLite.
  list-repos                 List registered repositories.
  sync-merges                Sync merged PR/default-branch events for one repository.
  audit-merge-event          Audit one persisted merge event.
  audit-pending-merges       Audit pending merge events.
  merge-history              List merge events and linked audit runs.
  report                     Generate a local compliance report.

Common options:
  --repo <path>              Repository path. Default: .
  --profile <profile>        standard, strict, or security. Default: security
  --format <format>          markdown, json, or github. Default: markdown
  --fail-on <band>           none, critical, high, medium, low, or info. Default: none
  --db <path>                Optional local SQLite audit DB path.

Examples:
  mcp-compliance-scan review --repo . --mode range --base origin/main --target HEAD --profile security --fail-on high
  mcp-compliance-scan audit-merge --repo . --base "$GITHUB_EVENT_BEFORE" --target "$GITHUB_SHA" --format github --fail-on high
  mcp-compliance-scan sync-github-repos --owner your-org --owner-type org
`;

export async function runCli(argv: string[], io: CliIO = defaultIO): Promise<number> {
  const [command, ...rest] = argv;
  const args = parseArgs(rest);

  try {
    if (!command || command === "help" || command === "--help" || command === "-h") {
      io.stdout(HELP);
      return 0;
    }

    switch (command) {
      case "review":
        return await reviewCommand(args, io, false);
      case "audit-merge":
        return await reviewCommand(args, io, true);
      case "init-db":
        return initDbCommand(args, io);
      case "history":
        return historyCommand(args, io);
      case "trends":
        return trendsCommand(args, io);
      case "standards":
        return standardsCommand(args, io);
      case "sync-github-repos":
        return await syncGithubReposCommand(args, io);
      case "list-repos":
        return listReposCommand(args, io);
      case "sync-merges":
        return await syncMergesCommand(args, io);
      case "audit-merge-event":
        return await auditMergeEventCommand(args, io);
      case "audit-pending-merges":
        return await auditPendingMergesCommand(args, io);
      case "merge-history":
        return mergeHistoryCommand(args, io);
      case "report":
        return reportCommand(args, io);
      default:
        io.stderr(`Unknown command: ${command}\n\n${HELP}`);
        return 2;
    }
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

async function reviewCommand(args: ParsedArgs, io: CliIO, exact: boolean): Promise<number> {
  const repoPath = stringArg(args, "repo", ".");
  const profile = profileArg(args, "profile", "security");
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const failOn = failBandArg(args, "fail-on", "none");
  const maxBytes = numberArg(args, "max-bytes", 512_000);
  const maxFindings = numberArg(args, "max-findings", 50);
  const language = optionalStringArg(args, "language");
  const framework = optionalStringArg(args, "framework");
  const riskAreas = stringListArg(args, "risk-area", "risk-areas");
  const persist = booleanArg(args, "persist", false);
  const dbPath = optionalStringArg(args, "db");
  const repoDiff = exact
    ? await getRepositoryExactDiff({
        repoPath,
        baseRef: requiredStringArg(args, "base"),
        targetRef: requiredStringArg(args, "target"),
        maxBytes
      })
    : await getRepositoryDiff({
        repoPath,
        mode: reviewModeArg(args, "mode", "working-tree"),
        baseRef: optionalStringArg(args, "base"),
        targetRef: optionalStringArg(args, "target"),
        includeUntracked: booleanArg(args, "include-untracked", true),
        maxBytes
      });
  const report = reviewDiff(repoDiff.diffText, {
    profile,
    maxFindings,
    language,
    framework,
    riskAreas,
    truncated: repoDiff.truncated
  });
  const priorityPlan = prioritizeFindings(report.findings);
  const persisted = persist
    ? persistAuditRun({
        dbPath,
        repoDiff,
        report,
        reviewRequest: {
          source: exact ? "cli_audit_merge" : "cli_review",
          repoPath,
          profile,
          language,
          framework,
          riskAreas
        }
      })
    : undefined;
  const payload = {
    repository: {
      root: repoDiff.repoRoot,
      command: repoDiff.command,
      diffBytes: Buffer.byteLength(repoDiff.diffText, "utf8"),
      truncated: repoDiff.truncated,
      persisted
    },
    review: report,
    priorityPlan
  };

  emitReviewOutput(io, outputFormat, payload);
  return shouldFail(priorityPlan.counts, failOn) ? 1 : 0;
}

function initDbCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = initAuditDatabase({ dbPath: optionalStringArg(args, "db") });
  emit(io, outputFormat, result, [
    "# Audit Database",
    "",
    `Database: ${result.dbPath}`,
    `Schema: ${result.schemaPath}`,
    `Initialized: ${result.initialized}`
  ].join("\n"));
  return 0;
}

function historyCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = listAuditRuns({
    dbPath: optionalStringArg(args, "db"),
    limit: numberArg(args, "limit", 20)
  });
  emit(io, outputFormat, result, formatAuditHistoryMarkdown(result));
  return 0;
}

function trendsCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = summarizeAuditTrends({
    dbPath: optionalStringArg(args, "db"),
    days: numberArg(args, "days", 30)
  });
  emit(io, outputFormat, result, formatAuditTrendsMarkdown(result));
  return 0;
}

function standardsCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  emit(io, outputFormat, { standards: STANDARDS_CATALOG }, formatStandardsCatalogMarkdown());
  return 0;
}

async function syncGithubReposCommand(args: ParsedArgs, io: CliIO): Promise<number> {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = await syncGithubRepositories({
    dbPath: optionalStringArg(args, "db"),
    owner: optionalStringArg(args, "owner"),
    ownerType: ownerTypeArg(args, "owner-type", "user"),
    includeArchived: booleanArg(args, "include-archived", false),
    limit: numberArg(args, "limit", 500)
  });
  const markdown = [
    "# GitHub Repository Sync",
    "",
    `Database: ${result.dbPath}`,
    `Synced: ${result.syncedAt}`,
    `Repositories: ${result.repositoryCount}`,
    "",
    ...result.repositories.slice(0, 50).map((repo) => `- ${repo.name} (${repo.riskTier}, ${repo.scanProfile})`)
  ].join("\n");
  emit(io, outputFormat, result, markdown);
  return 0;
}

function listReposCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = listRegisteredRepositories({
    dbPath: optionalStringArg(args, "db"),
    includeInventoryOnly: booleanArg(args, "include-inventory-only", false),
    limit: numberArg(args, "limit", 500)
  });
  emit(io, outputFormat, result, formatRepositoryListMarkdown(result));
  return 0;
}

async function syncMergesCommand(args: ParsedArgs, io: CliIO): Promise<number> {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = await syncRepositoryMerges({
    dbPath: optionalStringArg(args, "db"),
    repository: requiredStringArg(args, "repository"),
    branch: optionalStringArg(args, "branch"),
    since: optionalStringArg(args, "since"),
    days: numberArg(args, "days", 30),
    limit: numberArg(args, "limit", 100),
    includeDefaultBranchCommits: booleanArg(args, "include-default-branch-commits", true)
  });
  const markdown = [
    "# Merge Sync",
    "",
    `Repository: ${result.repository.name}`,
    `Branch: ${result.branch}`,
    `Merge events: ${result.mergeEventCount}`
  ].join("\n");
  emit(io, outputFormat, result, markdown);
  return 0;
}

async function auditMergeEventCommand(args: ParsedArgs, io: CliIO): Promise<number> {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = await auditMergeEvent({
    dbPath: optionalStringArg(args, "db"),
    mergeEventId: requiredStringArg(args, "merge-event-id"),
    repoPath: optionalStringArg(args, "repo"),
    checkoutRoot: optionalStringArg(args, "checkout-root"),
    maxBytes: numberArg(args, "max-bytes", 512_000),
    profile: profileArg(args, "profile", "security"),
    maxFindings: numberArg(args, "max-findings", 50),
    language: optionalStringArg(args, "language"),
    framework: optionalStringArg(args, "framework"),
    riskAreas: stringListArg(args, "risk-area", "risk-areas")
  });
  emit(io, outputFormat, result, result.reviewMarkdown);
  return 0;
}

async function auditPendingMergesCommand(args: ParsedArgs, io: CliIO): Promise<number> {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = await auditUnprocessedMerges({
    dbPath: optionalStringArg(args, "db"),
    repository: optionalStringArg(args, "repository"),
    checkoutRoot: optionalStringArg(args, "checkout-root"),
    limit: numberArg(args, "limit", 20),
    maxBytes: numberArg(args, "max-bytes", 512_000),
    profile: profileArg(args, "profile", "security"),
    maxFindings: numberArg(args, "max-findings", 50)
  });
  const markdown = [
    "# Pending Merge Audits",
    "",
    `Processed: ${result.processed.length}`,
    `Errors: ${result.errors.length}`
  ].join("\n");
  emit(io, outputFormat, result, markdown);
  return result.errors.length > 0 ? 1 : 0;
}

function mergeHistoryCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = outputFormatArg(args, "format", "markdown");
  const result = mergeAuditHistory({
    dbPath: optionalStringArg(args, "db"),
    repository: optionalStringArg(args, "repository"),
    limit: numberArg(args, "limit", 50)
  });
  emit(io, outputFormat, result, formatMergeHistoryMarkdown(result));
  return 0;
}

function reportCommand(args: ParsedArgs, io: CliIO): number {
  const outputFormat = reportOutputFormatArg(args, "format", "markdown");
  const result = generateComplianceReport({
    dbPath: optionalStringArg(args, "db"),
    scope: reportScopeArg(args, "scope", "portfolio"),
    repository: optionalStringArg(args, "repository"),
    auditRunId: optionalStringArg(args, "audit-run-id") ?? optionalStringArg(args, "audit-run"),
    days: numberArg(args, "days", 30),
    limit: numberArg(args, "limit", 20)
  });
  emitReport(io, outputFormat, result, formatComplianceReportMarkdown(result));
  return 0;
}

function emitReviewOutput(io: CliIO, outputFormat: OutputFormat, payload: {
  repository: Record<string, unknown>;
  review: ReturnType<typeof reviewDiff>;
  priorityPlan: ReturnType<typeof prioritizeFindings>;
}): void {
  if (outputFormat === "json") {
    io.stdout(`${JSON.stringify(payload, null, 2)}\n`);
    return;
  }

  if (outputFormat === "github") {
    for (const finding of payload.priorityPlan.orderedFindings) {
      const level = finding.priority.band === "critical" || finding.priority.band === "high" ? "error" : "warning";
      const file = finding.file ? ` file=${escapeGithubAnnotation(finding.file)},` : "";
      const line = finding.line ? `line=${finding.line},` : "";
      io.stdout(`::${level}${file}${line}title=${escapeGithubAnnotation(`[${finding.priority.band}] ${finding.title}`)}::${escapeGithubAnnotation(finding.remediation)}\n`);
    }
    io.stdout(`${payload.review.summary}\n`);
    return;
  }

  const priorityMarkdown = payload.priorityPlan.findingCount > 0
    ? `\n${formatPriorityPlanMarkdown(payload.priorityPlan)}`
    : "";
  io.stdout(`${formatReviewMarkdown(payload.review)}${priorityMarkdown}`);
}

function emit(io: CliIO, outputFormat: OutputFormat, payload: unknown, markdown: string): void {
  io.stdout(outputFormat === "json" ? `${JSON.stringify(payload, null, 2)}\n` : `${markdown.trimEnd()}\n`);
}

function emitReport(io: CliIO, outputFormat: ReportOutputFormat, payload: unknown, markdown: string): void {
  io.stdout(outputFormat === "json" ? `${JSON.stringify(payload, null, 2)}\n` : `${markdown.trimEnd()}\n`);
}

function shouldFail(counts: Record<PriorityBand, number>, failOn: FailBand): boolean {
  if (failOn === "none") {
    return false;
  }
  const threshold = BAND_ORDER[failOn];
  return Object.entries(counts).some(([band, count]) => count > 0 && BAND_ORDER[band as PriorityBand] >= threshold);
}

type ParsedArgs = Record<string, string | boolean | string[]>;

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = {};

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]!;
    if (!token.startsWith("--")) {
      appendArg(parsed, "_", token);
      continue;
    }

    const withoutPrefix = token.slice(2);
    const equalsIndex = withoutPrefix.indexOf("=");
    if (equalsIndex >= 0) {
      setArg(parsed, withoutPrefix.slice(0, equalsIndex), withoutPrefix.slice(equalsIndex + 1));
      continue;
    }

    if (withoutPrefix.startsWith("no-")) {
      setArg(parsed, withoutPrefix.slice(3), false);
      continue;
    }

    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      setArg(parsed, withoutPrefix, next);
      index += 1;
    } else {
      setArg(parsed, withoutPrefix, true);
    }
  }

  return parsed;
}

function setArg(parsed: ParsedArgs, key: string, value: string | boolean): void {
  if (key in parsed) {
    appendArg(parsed, key, String(value));
    return;
  }
  parsed[key] = value;
}

function appendArg(parsed: ParsedArgs, key: string, value: string): void {
  const existing = parsed[key];
  if (Array.isArray(existing)) {
    existing.push(value);
  } else if (typeof existing === "string") {
    parsed[key] = [existing, value];
  } else {
    parsed[key] = [value];
  }
}

function stringArg(args: ParsedArgs, key: string, fallback: string): string {
  return optionalStringArg(args, key) ?? fallback;
}

function requiredStringArg(args: ParsedArgs, key: string): string {
  const value = optionalStringArg(args, key);
  if (!value) {
    throw new Error(`Missing required option --${key}`);
  }
  return value;
}

function optionalStringArg(args: ParsedArgs, key: string): string | undefined {
  const value = args[key];
  if (Array.isArray(value)) {
    return value.at(-1);
  }
  return typeof value === "string" ? value : undefined;
}

function booleanArg(args: ParsedArgs, key: string, fallback: boolean): boolean {
  const value = args[key];
  return typeof value === "boolean" ? value : fallback;
}

function numberArg(args: ParsedArgs, key: string, fallback: number): number {
  const value = optionalStringArg(args, key);
  if (!value) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Expected --${key} to be a number.`);
  }
  return parsed;
}

function stringListArg(args: ParsedArgs, repeatedKey: string, commaKey: string): string[] | undefined {
  const values: string[] = [];
  const repeated = args[repeatedKey];
  if (Array.isArray(repeated)) {
    values.push(...repeated);
  } else if (typeof repeated === "string") {
    values.push(repeated);
  }
  const commaValue = optionalStringArg(args, commaKey);
  if (commaValue) {
    values.push(...commaValue.split(",").map((item) => item.trim()).filter(Boolean));
  }
  return values.length > 0 ? values : undefined;
}

function profileArg(args: ParsedArgs, key: string, fallback: ReviewProfile): ReviewProfile {
  const value = stringArg(args, key, fallback);
  if (value !== "standard" && value !== "strict" && value !== "security") {
    throw new Error(`Expected --${key} to be standard, strict, or security.`);
  }
  return value;
}

function outputFormatArg(args: ParsedArgs, key: string, fallback: OutputFormat): OutputFormat {
  const value = stringArg(args, key, fallback);
  if (value !== "markdown" && value !== "json" && value !== "github") {
    throw new Error(`Expected --${key} to be markdown, json, or github.`);
  }
  return value;
}

function reportOutputFormatArg(args: ParsedArgs, key: string, fallback: ReportOutputFormat): ReportOutputFormat {
  const value = stringArg(args, key, fallback);
  if (value !== "markdown" && value !== "json") {
    throw new Error(`Expected --${key} to be markdown or json.`);
  }
  return value;
}

function failBandArg(args: ParsedArgs, key: string, fallback: FailBand): FailBand {
  const value = stringArg(args, key, fallback);
  if (value !== "none" && value !== "critical" && value !== "high" && value !== "medium" && value !== "low" && value !== "info") {
    throw new Error(`Expected --${key} to be none, critical, high, medium, low, or info.`);
  }
  return value;
}

function reviewModeArg(args: ParsedArgs, key: string, fallback: ReviewMode): ReviewMode {
  const value = stringArg(args, key, fallback);
  if (value !== "working-tree" && value !== "staged" && value !== "range") {
    throw new Error(`Expected --${key} to be working-tree, staged, or range.`);
  }
  return value;
}

function ownerTypeArg(args: ParsedArgs, key: string, fallback: "user" | "org"): "user" | "org" {
  const value = stringArg(args, key, fallback);
  if (value !== "user" && value !== "org") {
    throw new Error(`Expected --${key} to be user or org.`);
  }
  return value;
}

function reportScopeArg(args: ParsedArgs, key: string, fallback: ComplianceReportScope): ComplianceReportScope {
  const value = stringArg(args, key, fallback);
  if (value !== "portfolio" && value !== "repository" && value !== "audit_run" && value !== "merge_window") {
    throw new Error(`Expected --${key} to be portfolio, repository, audit_run, or merge_window.`);
  }
  return value;
}

function escapeGithubAnnotation(value: string): string {
  return value
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A")
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

const defaultIO: CliIO = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text)
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const code = await runCli(process.argv.slice(2));
  process.exitCode = code;
}
