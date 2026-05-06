import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuditDatabaseOptions, initAuditDatabase } from "./audit.js";
import { PriorityBand } from "./priority.js";
import { Severity } from "./review.js";
import { STANDARDS_CATALOG } from "./standards.js";

export type ComplianceReportScope = "portfolio" | "repository" | "audit_run" | "merge_window";
export type MergeStatus = "pending" | "audited" | "skipped" | "error";

export interface ComplianceReportOptions extends AuditDatabaseOptions {
  scope?: ComplianceReportScope;
  repository?: string;
  auditRunId?: string;
  days?: number;
  limit?: number;
}

export interface ComplianceReport {
  reportVersion: "compliance-report-v1";
  generatedAt: string;
  dbPath: string;
  scope: ComplianceReportScope;
  filters: {
    repository?: string;
    auditRunId?: string;
    days?: number;
    limit: number;
    windowStart?: string;
    previousWindowStart?: string;
  };
  executiveSummary: string[];
  summary: {
    repositoryCount: number;
    trackedRepositoryCount: number;
    auditRunCount: number;
    mergeEventCount: number;
    auditedMergeCount: number;
    pendingMergeCount: number;
    findingCount: number;
    openFindingCount: number;
    priorityCounts: Record<PriorityBand, number>;
    openPriorityCounts: Record<PriorityBand, number>;
    severityCounts: Record<Severity, number>;
  };
  repositories: RepositoryReportRow[];
  mergeCoverage: {
    coveragePercent: number;
    byStatus: Record<MergeStatus, number>;
    latestMergedAt?: string;
    oldestMergedAt?: string;
  };
  findingsByPriority: PriorityReportRow[];
  findingsByControl: ControlReportRow[];
  remediationQueue: RemediationQueueItem[];
  recentChanges: {
    windowDays: number;
    currentWindowFindingCount: number;
    previousWindowFindingCount: number;
    findingDelta: number;
    currentOpenPriorityCounts: Record<PriorityBand, number>;
    previousOpenPriorityCounts: Record<PriorityBand, number>;
    openPriorityDeltas: Record<PriorityBand, number>;
    nonOpenFindingsInWindow: number;
  };
  pendingUnauditedMerges: PendingMergeReportRow[];
  standardsSnapshot: {
    catalogHash: string;
    catalogCount: number;
    observedAuditSnapshotHashes: string[];
    standards: Array<{
      id: string;
      name: string;
      authority: string;
      version: string;
      domains: string[];
      url: string;
    }>;
  };
  evidence: {
    generatedBy: string;
    packageVersion: string;
    auditDbPath: string;
    engineVersions: string[];
    latestAuditRunAt?: string;
    latestMergeAt?: string;
  };
}

export interface RepositoryReportRow {
  id: string;
  name: string;
  remoteUrl?: string;
  visibility?: string;
  riskTier: string;
  scanProfile: string;
  trackMerges: boolean;
  trackedBranches: string[];
  lastMergeSyncAt?: string;
  auditRunCount: number;
  mergeEventCount: number;
  auditedMergeCount: number;
  pendingMergeCount: number;
  findingCount: number;
  openFindingCount: number;
}

export interface PriorityReportRow {
  priority: PriorityBand;
  findingCount: number;
  openFindingCount: number;
  blocker: number;
  high: number;
  medium: number;
  low: number;
}

export interface ControlReportRow {
  standardId: string;
  standardName?: string;
  standardVersion?: string;
  control: string;
  title: string;
  findingCount: number;
  openFindingCount: number;
  priorityCounts: Record<PriorityBand, number>;
}

export interface RemediationQueueItem {
  rank: number;
  findingId: string;
  auditRunId: string;
  repositoryName?: string;
  priority: PriorityBand;
  score: number;
  severity: Severity;
  ruleKey: string;
  title: string;
  status: string;
  location: string;
  standards: string[];
  remediation?: string;
  mergeEventId?: string;
  mergedAt?: string;
}

export interface PendingMergeReportRow {
  id: string;
  repositoryName: string;
  eventType: string;
  branch: string;
  mergeCommitSha: string;
  prNumber?: number;
  title?: string;
  author?: string;
  mergedAt: string;
  htmlUrl?: string;
}

type SqlValue = string | number | null;

interface ReportContext {
  scope: ComplianceReportScope;
  repository?: string;
  auditRunId?: string;
  days: number;
  limit: number;
  windowStart?: string;
  previousWindowStart?: string;
}

interface RawRepositoryRow {
  id: string;
  name: string;
  remoteUrl?: string;
  visibility?: string;
  riskTier: string;
  scanProfile: string;
  trackMerges: boolean;
  trackedBranches: string[];
  lastMergeSyncAt?: string;
}

interface RawAuditRunRow {
  id: string;
  repositoryId?: string;
  repositoryName?: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  engineVersion: string;
  engineCommit?: string;
  standardsSnapshotHash?: string;
}

interface RawMergeEventRow {
  id: string;
  repositoryId: string;
  repositoryName: string;
  eventType: string;
  branch: string;
  mergeCommitSha: string;
  prNumber?: number;
  title?: string;
  author?: string;
  mergedAt: string;
  htmlUrl?: string;
  auditRunId?: string;
  status: MergeStatus;
}

interface RawFindingRow {
  id: string;
  auditRunId: string;
  repositoryId?: string;
  repositoryName?: string;
  ruleKey: string;
  severity: Severity;
  status: string;
  filePath?: string;
  lineNumber?: number;
  title: string;
  remediation?: string;
  confidence: number;
  createdAt: string;
  metadata: Record<string, unknown>;
  priority: PriorityBand;
  priorityScore: number;
  controls: ControlRef[];
}

interface ControlRef {
  standardId: string;
  standardName?: string;
  standardVersion?: string;
  control: string;
  title: string;
}

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PRIORITY_ORDER: PriorityBand[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_ORDER: Severity[] = ["blocker", "high", "medium", "low"];
const MERGE_STATUSES: MergeStatus[] = ["pending", "audited", "skipped", "error"];
const MS_PER_DAY = 24 * 60 * 60 * 1000;

export function generateComplianceReport(options: ComplianceReportOptions = {}): ComplianceReport {
  const scope = options.scope ?? "portfolio";
  const days = options.days ?? 30;
  const limit = options.limit ?? 20;
  validateReportOptions({ ...options, scope, days, limit });

  const { dbPath } = initAuditDatabase(options);
  const db = new DatabaseSync(dbPath, { readOnly: true });
  db.exec("PRAGMA foreign_keys = ON");

  const now = new Date();
  const context: ReportContext = {
    scope,
    repository: options.repository,
    auditRunId: options.auditRunId,
    days,
    limit,
    windowStart: scope === "merge_window" ? new Date(now.getTime() - days * MS_PER_DAY).toISOString() : undefined,
    previousWindowStart: new Date(now.getTime() - days * 2 * MS_PER_DAY).toISOString()
  };

  try {
    assertScopeTargetsExist(db, context);
    const repositories = queryRepositories(db, context);
    const repositoryIds = repositories.map((repository) => repository.id);
    const mergeEvents = queryMergeEvents(db, context, repositoryIds);
    const auditRuns = queryAuditRuns(db, context, repositoryIds, mergeEvents);
    const auditRunIds = auditRuns.map((auditRun) => auditRun.id);
    const findings = queryFindings(db, auditRunIds);
    attachControls(db, findings);

    const repositoryReportRows = buildRepositoryRows(repositories, auditRuns, mergeEvents, findings);
    const mergeCoverage = buildMergeCoverage(mergeEvents);
    const priorityCounts = countByPriority(findings);
    const openPriorityCounts = countByPriority(findings.filter((finding) => finding.status === "open"));
    const severityCounts = countBySeverity(findings);
    const pendingUnauditedMerges = mergeEvents
      .filter((event) => event.status === "pending")
      .sort((left, right) => right.mergedAt.localeCompare(left.mergedAt))
      .slice(0, limit)
      .map(rowToPendingMerge);
    const findingsByPriority = buildFindingsByPriority(findings);
    const findingsByControl = buildFindingsByControl(findings, limit);
    const remediationQueue = buildRemediationQueue(findings, mergeEvents, limit);
    const recentChanges = buildRecentChanges(db, context, repositoryIds);
    const standardsSnapshot = buildStandardsSnapshot(auditRuns);
    const evidence = buildEvidence(dbPath, auditRuns, mergeEvents);
    const summary = {
      repositoryCount: repositories.length,
      trackedRepositoryCount: repositories.filter((repository) => repository.trackMerges).length,
      auditRunCount: auditRuns.length,
      mergeEventCount: mergeEvents.length,
      auditedMergeCount: mergeEvents.filter((event) => event.status === "audited").length,
      pendingMergeCount: mergeEvents.filter((event) => event.status === "pending").length,
      findingCount: findings.length,
      openFindingCount: findings.filter((finding) => finding.status === "open").length,
      priorityCounts,
      openPriorityCounts,
      severityCounts
    };

    return {
      reportVersion: "compliance-report-v1",
      generatedAt: now.toISOString(),
      dbPath,
      scope,
      filters: {
        repository: options.repository,
        auditRunId: options.auditRunId,
        days,
        limit,
        windowStart: context.windowStart,
        previousWindowStart: context.previousWindowStart
      },
      executiveSummary: buildExecutiveSummary(summary, mergeCoverage, remediationQueue.length, standardsSnapshot),
      summary,
      repositories: repositoryReportRows,
      mergeCoverage,
      findingsByPriority,
      findingsByControl,
      remediationQueue,
      recentChanges,
      pendingUnauditedMerges,
      standardsSnapshot,
      evidence
    };
  } finally {
    db.close();
  }
}

export function formatComplianceReportMarkdown(report: ComplianceReport): string {
  const lines = [
    "# Compliance Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Scope: ${report.scope}`,
    report.filters.repository ? `Repository: ${report.filters.repository}` : undefined,
    report.filters.auditRunId ? `Audit run: ${report.filters.auditRunId}` : undefined,
    report.filters.windowStart ? `Window start: ${report.filters.windowStart}` : undefined,
    `Database: ${report.dbPath}`,
    "",
    "## Executive Summary",
    "",
    ...report.executiveSummary.map((item) => `- ${item}`),
    "",
    "## Repositories Covered",
    "",
    "| Repository | Tier | Profile | Track Merges | Audit Runs | Merges | Pending | Open Findings |",
    "| --- | --- | --- | --- | ---: | ---: | ---: | ---: |",
    ...orEmptyRows(report.repositories.map((repository) => `| ${cell(repository.name)} | ${cell(repository.riskTier)} | ${cell(repository.scanProfile)} | ${repository.trackMerges ? "yes" : "no"} | ${repository.auditRunCount} | ${repository.mergeEventCount} | ${repository.pendingMergeCount} | ${repository.openFindingCount} |`), 8),
    "",
    "## Merge And Audit Coverage",
    "",
    `Coverage: ${report.mergeCoverage.coveragePercent.toFixed(1)}% (${report.summary.auditedMergeCount}/${report.summary.mergeEventCount} merge events audited)`,
    `Pending merge events: ${report.summary.pendingMergeCount}`,
    report.mergeCoverage.latestMergedAt ? `Latest merge: ${report.mergeCoverage.latestMergedAt}` : "Latest merge: none",
    "",
    "| Status | Count |",
    "| --- | ---: |",
    ...MERGE_STATUSES.map((status) => `| ${status} | ${report.mergeCoverage.byStatus[status]} |`),
    "",
    "## Current Findings By Priority",
    "",
    "| Priority | Open | Total | Blocker | High | Medium | Low |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...report.findingsByPriority.map((row) => `| ${row.priority} | ${row.openFindingCount} | ${row.findingCount} | ${row.blocker} | ${row.high} | ${row.medium} | ${row.low} |`),
    "",
    "## Findings By Standard Control",
    "",
    "| Standard Control | Open | Total | Critical | High | Medium | Low |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...orEmptyRows(report.findingsByControl.map((row) => `| ${cell(`${row.standardId}:${row.control}`)} | ${row.openFindingCount} | ${row.findingCount} | ${row.priorityCounts.critical} | ${row.priorityCounts.high} | ${row.priorityCounts.medium} | ${row.priorityCounts.low} |`), 7),
    "",
    "## Critical And High Remediation Queue",
    "",
    "| Rank | Priority | Score | Repository | Rule | Location | Standards |",
    "| ---: | --- | ---: | --- | --- | --- | --- |",
    ...orEmptyRows(report.remediationQueue.map((item) => `| ${item.rank} | ${item.priority} | ${item.score} | ${cell(item.repositoryName ?? "unknown")} | ${cell(item.ruleKey)} | ${cell(item.location)} | ${cell(item.standards.join(", ") || "none")} |`), 7),
    "",
    "## Recent Improvements And Regressions",
    "",
    `Window: ${report.recentChanges.windowDays} days`,
    `Current window findings: ${report.recentChanges.currentWindowFindingCount}`,
    `Previous window findings: ${report.recentChanges.previousWindowFindingCount}`,
    `Finding delta: ${signed(report.recentChanges.findingDelta)}`,
    `Non-open findings recorded in current window: ${report.recentChanges.nonOpenFindingsInWindow}`,
    "",
    "| Priority | Current Open | Previous Open | Delta |",
    "| --- | ---: | ---: | ---: |",
    ...PRIORITY_ORDER.map((priority) => `| ${priority} | ${report.recentChanges.currentOpenPriorityCounts[priority]} | ${report.recentChanges.previousOpenPriorityCounts[priority]} | ${signed(report.recentChanges.openPriorityDeltas[priority])} |`),
    "",
    "## Pending Unaudited Merges",
    "",
    "| Merge Event | Repository | Branch | Merged | Commit | Title |",
    "| --- | --- | --- | --- | --- | --- |",
    ...orEmptyRows(report.pendingUnauditedMerges.map((event) => `| ${event.id} | ${cell(event.repositoryName)} | ${cell(event.branch)} | ${event.mergedAt} | ${event.mergeCommitSha.slice(0, 12)} | ${cell(event.title ?? "")} |`), 6),
    "",
    "## Standards Catalog Version Snapshot",
    "",
    `Catalog hash: ${report.standardsSnapshot.catalogHash}`,
    `Standards: ${report.standardsSnapshot.catalogCount}`,
    `Observed audit snapshot hashes: ${report.standardsSnapshot.observedAuditSnapshotHashes.join(", ") || "none"}`,
    "",
    "| Standard | Version | Domains | Source |",
    "| --- | --- | --- | --- |",
    ...report.standardsSnapshot.standards.map((standard) => `| ${cell(`${standard.authority}: ${standard.name}`)} | ${cell(standard.version)} | ${cell(standard.domains.join(", "))} | ${cell(standard.url)} |`),
    "",
    "## Evidence Metadata",
    "",
    `Generated by: ${report.evidence.generatedBy}`,
    `Package version: ${report.evidence.packageVersion}`,
    `Audit DB path: ${report.evidence.auditDbPath}`,
    `Engine versions observed: ${report.evidence.engineVersions.join(", ") || "none"}`,
    report.evidence.latestAuditRunAt ? `Latest audit run: ${report.evidence.latestAuditRunAt}` : "Latest audit run: none",
    report.evidence.latestMergeAt ? `Latest merge event: ${report.evidence.latestMergeAt}` : "Latest merge event: none"
  ].filter((line): line is string => line !== undefined);

  return `${lines.join("\n")}\n`;
}

function validateReportOptions(options: Required<Pick<ComplianceReportOptions, "scope" | "days" | "limit">> & ComplianceReportOptions): void {
  if (!["portfolio", "repository", "audit_run", "merge_window"].includes(options.scope)) {
    throw new Error("Expected report scope to be portfolio, repository, audit_run, or merge_window.");
  }
  if (options.scope === "repository" && !options.repository) {
    throw new Error("Repository report scope requires --repository.");
  }
  if (options.scope === "audit_run" && !options.auditRunId) {
    throw new Error("Audit run report scope requires --audit-run-id.");
  }
  if (!Number.isInteger(options.days) || options.days < 1 || options.days > 3650) {
    throw new Error("Expected report days to be an integer from 1 to 3650.");
  }
  if (!Number.isInteger(options.limit) || options.limit < 1 || options.limit > 500) {
    throw new Error("Expected report limit to be an integer from 1 to 500.");
  }
}

function assertScopeTargetsExist(db: DatabaseSync, context: ReportContext): void {
  if (context.repository) {
    const row = get(db, "SELECT id FROM repositories WHERE id = ? OR name = ?", [context.repository, context.repository]);
    if (!row) {
      throw new Error(`Repository not found in audit database: ${context.repository}. Run sync_github_repositories or persist an audit first.`);
    }
  }
  if (context.auditRunId) {
    const row = get(db, "SELECT id FROM audit_runs WHERE id = ?", [context.auditRunId]);
    if (!row) {
      throw new Error(`Audit run not found in audit database: ${context.auditRunId}.`);
    }
  }
}

function queryRepositories(db: DatabaseSync, context: ReportContext): RawRepositoryRow[] {
  const conditions: string[] = [];
  const values: SqlValue[] = [];

  if (context.repository) {
    conditions.push("(r.id = ? OR r.name = ?)");
    values.push(context.repository, context.repository);
  }

  if (context.scope === "audit_run") {
    conditions.push("r.id IN (SELECT repository_id FROM audit_runs WHERE id = ?)");
    values.push(context.auditRunId!);
  }

  const rows = all(db, `SELECT
      r.id, r.name, r.remote_url AS remoteUrl, r.visibility,
      COALESCE(p.risk_tier, 'tier_2') AS riskTier,
      COALESCE(p.scan_profile, 'security') AS scanProfile,
      COALESCE(p.track_merges, 1) AS trackMerges,
      COALESCE(p.tracked_branches_json, '[]') AS trackedBranchesJson,
      p.last_merge_sync_at AS lastMergeSyncAt
    FROM repositories r
    LEFT JOIN repository_policies p ON p.repository_id = r.id
    ${conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : ""}
    ORDER BY r.name ASC`, values);

  return rows.map((row) => ({
    id: String(row.id),
    name: String(row.name),
    remoteUrl: nullableString(row.remoteUrl),
    visibility: nullableString(row.visibility),
    riskTier: String(row.riskTier),
    scanProfile: String(row.scanProfile),
    trackMerges: Number(row.trackMerges ?? 1) === 1,
    trackedBranches: arrayOfStrings(parseJson(row.trackedBranchesJson)),
    lastMergeSyncAt: nullableString(row.lastMergeSyncAt)
  }));
}

function queryAuditRuns(db: DatabaseSync, context: ReportContext, repositoryIds: string[], mergeEvents: RawMergeEventRow[]): RawAuditRunRow[] {
  const conditions: string[] = [];
  const values: SqlValue[] = [];

  if (context.scope === "audit_run") {
    conditions.push("ar.id = ?");
    values.push(context.auditRunId!);
  } else if (context.scope === "merge_window") {
    const linkedAuditRunIds = [...new Set(mergeEvents.map((event) => event.auditRunId).filter((id): id is string => Boolean(id)))];
    if (linkedAuditRunIds.length === 0) {
      return [];
    }
    conditions.push(`ar.id IN (${placeholders(linkedAuditRunIds.length)})`);
    values.push(...linkedAuditRunIds);
  } else {
    if (repositoryIds.length === 0) {
      return [];
    }
    conditions.push(`ar.repository_id IN (${placeholders(repositoryIds.length)})`);
    values.push(...repositoryIds);
  }

  const rows = all(db, `SELECT
      ar.id, ar.repository_id AS repositoryId, r.name AS repositoryName,
      ar.status, ar.started_at AS startedAt, ar.completed_at AS completedAt,
      ar.engine_version AS engineVersion, ar.engine_commit AS engineCommit,
      ar.standards_snapshot_hash AS standardsSnapshotHash
    FROM audit_runs ar
    LEFT JOIN repositories r ON r.id = ar.repository_id
    WHERE ${conditions.join(" AND ")}
    ORDER BY ar.started_at DESC`, values);

  return rows.map((row) => ({
    id: String(row.id),
    repositoryId: nullableString(row.repositoryId),
    repositoryName: nullableString(row.repositoryName),
    status: String(row.status),
    startedAt: String(row.startedAt),
    completedAt: nullableString(row.completedAt),
    engineVersion: String(row.engineVersion),
    engineCommit: nullableString(row.engineCommit),
    standardsSnapshotHash: nullableString(row.standardsSnapshotHash)
  }));
}

function queryMergeEvents(db: DatabaseSync, context: ReportContext, repositoryIds: string[]): RawMergeEventRow[] {
  const conditions: string[] = [];
  const values: SqlValue[] = [];

  if (context.scope === "audit_run") {
    conditions.push("me.audit_run_id = ?");
    values.push(context.auditRunId!);
  } else {
    if (repositoryIds.length === 0) {
      return [];
    }
    conditions.push(`me.repository_id IN (${placeholders(repositoryIds.length)})`);
    values.push(...repositoryIds);
  }

  if (context.scope === "merge_window") {
    conditions.push("me.merged_at >= ?");
    values.push(context.windowStart!);
  }

  const rows = all(db, `SELECT
      me.id, me.repository_id AS repositoryId, r.name AS repositoryName,
      me.event_type AS eventType, me.branch, me.merge_commit_sha AS mergeCommitSha,
      me.pr_number AS prNumber, me.title, me.author, me.merged_at AS mergedAt,
      me.html_url AS htmlUrl, me.audit_run_id AS auditRunId, me.status
    FROM merge_events me
    JOIN repositories r ON r.id = me.repository_id
    WHERE ${conditions.join(" AND ")}
    ORDER BY me.merged_at DESC`, values);

  return rows.map((row) => ({
    id: String(row.id),
    repositoryId: String(row.repositoryId),
    repositoryName: String(row.repositoryName),
    eventType: String(row.eventType),
    branch: String(row.branch),
    mergeCommitSha: String(row.mergeCommitSha),
    prNumber: nullableNumber(row.prNumber),
    title: nullableString(row.title),
    author: nullableString(row.author),
    mergedAt: String(row.mergedAt),
    htmlUrl: nullableString(row.htmlUrl),
    auditRunId: nullableString(row.auditRunId),
    status: row.status as MergeStatus
  }));
}

function queryFindings(db: DatabaseSync, auditRunIds: string[]): RawFindingRow[] {
  if (auditRunIds.length === 0) {
    return [];
  }

  const rows = all(db, `SELECT
      f.id, f.audit_run_id AS auditRunId, ar.repository_id AS repositoryId, r.name AS repositoryName,
      f.rule_key AS ruleKey, f.severity, f.status, f.file_path AS filePath,
      f.line_number AS lineNumber, f.title, f.remediation, f.confidence,
      f.created_at AS createdAt, f.metadata_json AS metadataJson
    FROM findings f
    JOIN audit_runs ar ON ar.id = f.audit_run_id
    LEFT JOIN repositories r ON r.id = ar.repository_id
    WHERE f.audit_run_id IN (${placeholders(auditRunIds.length)})
    ORDER BY f.created_at DESC`, auditRunIds);

  return rows.map((row) => {
    const metadata = parseJson(row.metadataJson) ?? {};
    const priority = priorityFromMetadata(metadata, row.severity as Severity);
    return {
      id: String(row.id),
      auditRunId: String(row.auditRunId),
      repositoryId: nullableString(row.repositoryId),
      repositoryName: nullableString(row.repositoryName),
      ruleKey: String(row.ruleKey),
      severity: row.severity as Severity,
      status: String(row.status),
      filePath: nullableString(row.filePath),
      lineNumber: nullableNumber(row.lineNumber),
      title: String(row.title),
      remediation: nullableString(row.remediation),
      confidence: Number(row.confidence ?? 0),
      createdAt: String(row.createdAt),
      metadata,
      priority: priority.band,
      priorityScore: priority.score,
      controls: []
    };
  });
}

function attachControls(db: DatabaseSync, findings: RawFindingRow[]): void {
  if (findings.length === 0) {
    return;
  }

  const controlsByFinding = new Map<string, ControlRef[]>();
  const rows = all(db, `SELECT
      fc.finding_id AS findingId,
      ss.id AS standardId,
      ss.name AS standardName,
      sv.version AS standardVersion,
      c.control_key AS control,
      c.title
    FROM finding_controls fc
    JOIN controls c ON c.id = fc.control_id
    JOIN standard_versions sv ON sv.id = c.standard_version_id
    JOIN standard_sources ss ON ss.id = sv.standard_source_id
    WHERE fc.finding_id IN (${placeholders(findings.length)})`, findings.map((finding) => finding.id));

  for (const row of rows) {
    const findingId = String(row.findingId);
    const controls = controlsByFinding.get(findingId) ?? [];
    controls.push({
      standardId: String(row.standardId),
      standardName: nullableString(row.standardName),
      standardVersion: nullableString(row.standardVersion),
      control: String(row.control),
      title: String(row.title)
    });
    controlsByFinding.set(findingId, controls);
  }

  for (const finding of findings) {
    finding.controls = controlsByFinding.get(finding.id) ?? [];
  }
}

function buildRepositoryRows(
  repositories: RawRepositoryRow[],
  auditRuns: RawAuditRunRow[],
  mergeEvents: RawMergeEventRow[],
  findings: RawFindingRow[]
): RepositoryReportRow[] {
  return repositories.map((repository) => {
    const repoAuditRuns = auditRuns.filter((auditRun) => auditRun.repositoryId === repository.id);
    const repoMergeEvents = mergeEvents.filter((event) => event.repositoryId === repository.id);
    const repoFindings = findings.filter((finding) => finding.repositoryId === repository.id);
    return {
      ...repository,
      auditRunCount: repoAuditRuns.length,
      mergeEventCount: repoMergeEvents.length,
      auditedMergeCount: repoMergeEvents.filter((event) => event.status === "audited").length,
      pendingMergeCount: repoMergeEvents.filter((event) => event.status === "pending").length,
      findingCount: repoFindings.length,
      openFindingCount: repoFindings.filter((finding) => finding.status === "open").length
    };
  }).sort((left, right) =>
    right.openFindingCount - left.openFindingCount ||
    right.pendingMergeCount - left.pendingMergeCount ||
    left.name.localeCompare(right.name)
  );
}

function buildMergeCoverage(mergeEvents: RawMergeEventRow[]): ComplianceReport["mergeCoverage"] {
  const byStatus = emptyMergeStatusCounts();
  for (const event of mergeEvents) {
    byStatus[event.status] += 1;
  }
  const audited = byStatus.audited;
  const total = mergeEvents.length;
  const sortedDates = mergeEvents.map((event) => event.mergedAt).sort();

  return {
    coveragePercent: total === 0 ? 100 : (audited / total) * 100,
    byStatus,
    oldestMergedAt: sortedDates.at(0),
    latestMergedAt: sortedDates.at(-1)
  };
}

function buildFindingsByPriority(findings: RawFindingRow[]): PriorityReportRow[] {
  return PRIORITY_ORDER.map((priority) => {
    const bucket = findings.filter((finding) => finding.priority === priority);
    return {
      priority,
      findingCount: bucket.length,
      openFindingCount: bucket.filter((finding) => finding.status === "open").length,
      blocker: bucket.filter((finding) => finding.severity === "blocker").length,
      high: bucket.filter((finding) => finding.severity === "high").length,
      medium: bucket.filter((finding) => finding.severity === "medium").length,
      low: bucket.filter((finding) => finding.severity === "low").length
    };
  });
}

function buildFindingsByControl(findings: RawFindingRow[], limit: number): ControlReportRow[] {
  const rows = new Map<string, ControlReportRow>();
  for (const finding of findings) {
    for (const control of finding.controls) {
      const key = `${control.standardId}:${control.standardVersion ?? ""}:${control.control}`;
      const row = rows.get(key) ?? {
        standardId: control.standardId,
        standardName: control.standardName,
        standardVersion: control.standardVersion,
        control: control.control,
        title: control.title,
        findingCount: 0,
        openFindingCount: 0,
        priorityCounts: emptyPriorityCounts()
      };
      row.findingCount += 1;
      if (finding.status === "open") {
        row.openFindingCount += 1;
      }
      row.priorityCounts[finding.priority] += 1;
      rows.set(key, row);
    }
  }

  return [...rows.values()]
    .sort((left, right) =>
      right.openFindingCount - left.openFindingCount ||
      right.findingCount - left.findingCount ||
      left.standardId.localeCompare(right.standardId) ||
      left.control.localeCompare(right.control)
    )
    .slice(0, limit);
}

function buildRemediationQueue(findings: RawFindingRow[], mergeEvents: RawMergeEventRow[], limit: number): RemediationQueueItem[] {
  const mergeByAuditRun = new Map(mergeEvents.filter((event) => event.auditRunId).map((event) => [event.auditRunId!, event]));
  return findings
    .filter((finding) => finding.status === "open" && (finding.priority === "critical" || finding.priority === "high"))
    .sort(compareFindingsByPriority)
    .slice(0, limit)
    .map((finding, index) => {
      const mergeEvent = mergeByAuditRun.get(finding.auditRunId);
      return {
        rank: index + 1,
        findingId: finding.id,
        auditRunId: finding.auditRunId,
        repositoryName: finding.repositoryName,
        priority: finding.priority,
        score: finding.priorityScore,
        severity: finding.severity,
        ruleKey: finding.ruleKey,
        title: finding.title,
        status: finding.status,
        location: locationForFinding(finding),
        standards: finding.controls.map((control) => `${control.standardId}:${control.control}`),
        remediation: finding.remediation,
        mergeEventId: mergeEvent?.id,
        mergedAt: mergeEvent?.mergedAt
      };
    });
}

function buildRecentChanges(db: DatabaseSync, context: ReportContext, repositoryIds: string[]): ComplianceReport["recentChanges"] {
  const windowStart = new Date(Date.now() - context.days * MS_PER_DAY).toISOString();
  const previousWindowStart = context.previousWindowStart ?? new Date(Date.now() - context.days * 2 * MS_PER_DAY).toISOString();
  const current = queryWindowFindings(db, repositoryIds, windowStart);
  const previous = queryWindowFindings(db, repositoryIds, previousWindowStart, windowStart);
  const currentOpenPriorityCounts = countByPriority(current.filter((finding) => finding.status === "open"));
  const previousOpenPriorityCounts = countByPriority(previous.filter((finding) => finding.status === "open"));
  const openPriorityDeltas = emptyPriorityCounts();
  for (const priority of PRIORITY_ORDER) {
    openPriorityDeltas[priority] = currentOpenPriorityCounts[priority] - previousOpenPriorityCounts[priority];
  }

  return {
    windowDays: context.days,
    currentWindowFindingCount: current.length,
    previousWindowFindingCount: previous.length,
    findingDelta: current.length - previous.length,
    currentOpenPriorityCounts,
    previousOpenPriorityCounts,
    openPriorityDeltas,
    nonOpenFindingsInWindow: current.filter((finding) => finding.status !== "open").length
  };
}

function queryWindowFindings(db: DatabaseSync, repositoryIds: string[], startAt: string, endBefore?: string): RawFindingRow[] {
  if (repositoryIds.length === 0) {
    return [];
  }
  const values: SqlValue[] = [...repositoryIds, startAt];
  const endCondition = endBefore ? "AND ar.started_at < ?" : "";
  if (endBefore) {
    values.push(endBefore);
  }

  const rows = all(db, `SELECT
      f.id, f.audit_run_id AS auditRunId, ar.repository_id AS repositoryId, r.name AS repositoryName,
      f.rule_key AS ruleKey, f.severity, f.status, f.file_path AS filePath,
      f.line_number AS lineNumber, f.title, f.remediation, f.confidence,
      f.created_at AS createdAt, f.metadata_json AS metadataJson
    FROM findings f
    JOIN audit_runs ar ON ar.id = f.audit_run_id
    LEFT JOIN repositories r ON r.id = ar.repository_id
    WHERE ar.repository_id IN (${placeholders(repositoryIds.length)})
      AND ar.started_at >= ?
      ${endCondition}`, values);

  return rows.map((row) => {
    const metadata = parseJson(row.metadataJson) ?? {};
    const priority = priorityFromMetadata(metadata, row.severity as Severity);
    return {
      id: String(row.id),
      auditRunId: String(row.auditRunId),
      repositoryId: nullableString(row.repositoryId),
      repositoryName: nullableString(row.repositoryName),
      ruleKey: String(row.ruleKey),
      severity: row.severity as Severity,
      status: String(row.status),
      filePath: nullableString(row.filePath),
      lineNumber: nullableNumber(row.lineNumber),
      title: String(row.title),
      remediation: nullableString(row.remediation),
      confidence: Number(row.confidence ?? 0),
      createdAt: String(row.createdAt),
      metadata,
      priority: priority.band,
      priorityScore: priority.score,
      controls: []
    };
  });
}

function buildStandardsSnapshot(auditRuns: RawAuditRunRow[]): ComplianceReport["standardsSnapshot"] {
  return {
    catalogHash: sha256(JSON.stringify(STANDARDS_CATALOG)),
    catalogCount: STANDARDS_CATALOG.length,
    observedAuditSnapshotHashes: [...new Set(auditRuns.map((auditRun) => auditRun.standardsSnapshotHash).filter((hash): hash is string => Boolean(hash)))].sort(),
    standards: STANDARDS_CATALOG.map((standard) => ({
      id: standard.id,
      name: standard.name,
      authority: standard.authority,
      version: standard.version,
      domains: standard.domains,
      url: standard.url
    }))
  };
}

function buildEvidence(dbPath: string, auditRuns: RawAuditRunRow[], mergeEvents: RawMergeEventRow[]): ComplianceReport["evidence"] {
  return {
    generatedBy: "mcp-compliance-scan",
    packageVersion: readPackageVersion(),
    auditDbPath: dbPath,
    engineVersions: [...new Set(auditRuns.map((auditRun) => auditRun.engineVersion))].filter(Boolean).sort(),
    latestAuditRunAt: auditRuns.map((auditRun) => auditRun.startedAt).sort().at(-1),
    latestMergeAt: mergeEvents.map((event) => event.mergedAt).sort().at(-1)
  };
}

function buildExecutiveSummary(
  summary: ComplianceReport["summary"],
  mergeCoverage: ComplianceReport["mergeCoverage"],
  remediationQueueCount: number,
  standardsSnapshot: ComplianceReport["standardsSnapshot"]
): string[] {
  return [
    `${summary.repositoryCount} repository record(s) covered; ${summary.trackedRepositoryCount} configured for merge tracking.`,
    `${summary.auditedMergeCount}/${summary.mergeEventCount} merge event(s) audited (${mergeCoverage.coveragePercent.toFixed(1)}% coverage); ${summary.pendingMergeCount} pending.`,
    `${summary.openFindingCount} open finding(s): critical ${summary.openPriorityCounts.critical}, high ${summary.openPriorityCounts.high}, medium ${summary.openPriorityCounts.medium}, low ${summary.openPriorityCounts.low}, info ${summary.openPriorityCounts.info}.`,
    `${remediationQueueCount} open critical/high remediation item(s) are queued.`,
    `${standardsSnapshot.catalogCount} standards are in the catalog; ${standardsSnapshot.observedAuditSnapshotHashes.length} audit standards snapshot hash(es) observed.`
  ];
}

function rowToPendingMerge(row: RawMergeEventRow): PendingMergeReportRow {
  return {
    id: row.id,
    repositoryName: row.repositoryName,
    eventType: row.eventType,
    branch: row.branch,
    mergeCommitSha: row.mergeCommitSha,
    prNumber: row.prNumber,
    title: row.title,
    author: row.author,
    mergedAt: row.mergedAt,
    htmlUrl: row.htmlUrl
  };
}

function countByPriority(findings: RawFindingRow[]): Record<PriorityBand, number> {
  const counts = emptyPriorityCounts();
  for (const finding of findings) {
    counts[finding.priority] += 1;
  }
  return counts;
}

function countBySeverity(findings: RawFindingRow[]): Record<Severity, number> {
  const counts = emptySeverityCounts();
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function priorityFromMetadata(metadata: Record<string, unknown>, severity: Severity): { band: PriorityBand; score: number } {
  const priority = isRecord(metadata.priority) ? metadata.priority : undefined;
  const band = typeof priority?.band === "string" && isPriorityBand(priority.band)
    ? priority.band
    : priorityBandForSeverity(severity);
  const score = typeof priority?.score === "number" ? priority.score : scoreForSeverity(severity);
  return { band, score };
}

function compareFindingsByPriority(left: RawFindingRow, right: RawFindingRow): number {
  return PRIORITY_ORDER.indexOf(left.priority) - PRIORITY_ORDER.indexOf(right.priority) ||
    right.priorityScore - left.priorityScore ||
    SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity) ||
    left.title.localeCompare(right.title);
}

function priorityBandForSeverity(severity: Severity): PriorityBand {
  switch (severity) {
    case "blocker":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
  }
}

function scoreForSeverity(severity: Severity): number {
  switch (severity) {
    case "blocker":
      return 100;
    case "high":
      return 70;
    case "medium":
      return 40;
    case "low":
      return 15;
  }
}

function locationForFinding(finding: RawFindingRow): string {
  if (!finding.filePath) {
    return "repository";
  }
  return finding.lineNumber ? `${finding.filePath}:${finding.lineNumber}` : finding.filePath;
}

function emptyPriorityCounts(): Record<PriorityBand, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function emptySeverityCounts(): Record<Severity, number> {
  return { blocker: 0, high: 0, medium: 0, low: 0 };
}

function emptyMergeStatusCounts(): Record<MergeStatus, number> {
  return { pending: 0, audited: 0, skipped: 0, error: 0 };
}

function orEmptyRows(rows: string[], columnCount: number): string[] {
  return rows.length > 0 ? rows : [`| ${Array.from({ length: columnCount }, (_, index) => index === 0 ? "none" : "").join(" | ")} |`];
}

function cell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function signed(value: number): string {
  return value > 0 ? `+${value}` : String(value);
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(",");
}

function all(db: DatabaseSync, sql: string, values: SqlValue[] = []): Array<Record<string, unknown>> {
  return db.prepare(sql).all(...values) as Array<Record<string, unknown>>;
}

function get(db: DatabaseSync, sql: string, values: SqlValue[] = []): Record<string, unknown> | undefined {
  return db.prepare(sql).get(...values) as Record<string, unknown> | undefined;
}

function parseJson(value: unknown): any {
  if (typeof value !== "string") {
    return undefined;
  }

  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function nullableString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nullableNumber(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPriorityBand(value: string): value is PriorityBand {
  return (PRIORITY_ORDER as string[]).includes(value);
}

function readPackageVersion(): string {
  const packagePath = path.join(PACKAGE_ROOT, "package.json");
  if (!existsSync(packagePath)) {
    return "0.0.0";
  }
  try {
    const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
    return String(packageJson.version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
