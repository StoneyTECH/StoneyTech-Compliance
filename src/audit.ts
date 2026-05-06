import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RepositoryDiff } from "./git.js";
import { FindingPriority, findingKey, prioritizeFindings } from "./priority.js";
import { ReviewFinding, ReviewReport, ReviewStatus, Severity } from "./review.js";
import {
  CHECKLIST_STANDARD_REFERENCES,
  RULE_STANDARD_REFERENCES,
  STANDARDS_CATALOG,
  StandardReference
} from "./standards.js";

export interface AuditDatabaseOptions {
  dbPath?: string;
}

export interface PersistAuditRunOptions extends AuditDatabaseOptions {
  repoDiff: RepositoryDiff;
  report: ReviewReport;
  reviewRequest: Record<string, unknown>;
}

export interface PersistedAuditRun {
  auditRunId: string;
  dbPath: string;
  repositoryId: string;
  repoSnapshotId: string;
  rulePackId: string;
  manifest: AuditManifest;
  findingIds: string[];
}

export interface AuditManifest {
  auditRunId: string;
  repository: {
    id: string;
    name: string;
    root: string;
    remoteUrl?: string;
    branch?: string;
    commitSha?: string;
  };
  diffHash: string;
  engineVersion: string;
  engineCommit?: string;
  rulePackId: string;
  rulePackVersion: string;
  standardsSnapshotHash: string;
  configHash: string;
  status: ReviewStatus;
  startedAt: string;
  completedAt: string;
}

export interface AuditRunSummary {
  id: string;
  repositoryName?: string;
  repositoryRemoteUrl?: string;
  status: ReviewStatus;
  startedAt: string;
  completedAt?: string;
  engineVersion: string;
  engineCommit?: string;
  blockerCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findingCount: number;
  summary: unknown;
}

export interface AuditRunDetail extends AuditRunSummary {
  metadata: unknown;
  findings: Array<ReviewFinding & {
    id: string;
    status: string;
    fingerprint: string;
    priority?: FindingPriority;
    controls: StandardReference[];
  }>;
}

export interface AuditTrends {
  dbPath: string;
  days: number;
  generatedAt: string;
  totals: Record<Severity, number> & { auditRuns: number; findings: number };
  byDay: Array<{
    day: string;
    auditRuns: number;
    blocker: number;
    high: number;
    medium: number;
    low: number;
    findings: number;
  }>;
  byRule: Array<{
    ruleKey: string;
    blocker: number;
    high: number;
    medium: number;
    low: number;
    findings: number;
  }>;
}

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_PATH = path.join(PACKAGE_ROOT, "schema", "audit-ledger.sql");

type SqlValue = string | number | null;

export function defaultAuditDbPath(): string {
  return path.resolve(process.env.MCP_COMPLIANCE_SCAN_DB ?? path.join(PACKAGE_ROOT, ".local", "audit", "compliance.db"));
}

export function initAuditDatabase(options: AuditDatabaseOptions = {}): { dbPath: string; schemaPath: string; initialized: boolean } {
  const dbPath = resolveAuditDbPath(options.dbPath);
  mkdirSync(path.dirname(dbPath), { recursive: true });
  const existed = existsSync(dbPath);
  const db = openDatabase(dbPath);

  try {
    db.exec(readFileSync(SCHEMA_PATH, "utf8"));
    seedStandards(db);
  } finally {
    db.close();
  }

  return {
    dbPath,
    schemaPath: SCHEMA_PATH,
    initialized: !existed
  };
}

export function persistAuditRun(options: PersistAuditRunOptions): PersistedAuditRun {
  const { dbPath } = initAuditDatabase(options);
  const db = openDatabase(dbPath);
  const startedAt = new Date().toISOString();
  const completedAt = startedAt;
  const repoMetadata = readRepositoryMetadata(options.repoDiff.repoRoot);
  const repositoryName = repoMetadata.remoteUrl ? repositoryNameFromRemote(repoMetadata.remoteUrl) : path.basename(options.repoDiff.repoRoot);
  const repositoryId = `repo_${shortHash(repoMetadata.remoteUrl ?? options.repoDiff.repoRoot)}`;
  const diffHash = sha256(options.repoDiff.diffText);
  const snapshotCommitSha = options.repoDiff.targetCommitSha ?? repoMetadata.commitSha;
  const snapshotBranch = options.repoDiff.branch ?? repoMetadata.branch;
  const repoSnapshotId = `snapshot_${shortHash(`${repositoryId}:${snapshotCommitSha ?? "unknown"}:${diffHash}`)}`;
  const engineVersion = readPackageVersion();
  const engineCommit = readEngineCommit();
  const standardsSnapshotHash = standardsSnapshotHashForCurrentCatalog();
  const configHash = sha256(JSON.stringify(options.reviewRequest));
  const rulePackVersion = `${engineVersion}+${shortHash(standardsSnapshotHash)}`;
  const rulePackId = `rulepack_${shortHash(`${engineVersion}:${standardsSnapshotHash}:${configHash}`)}`;
  const auditRunId = `audit_${startedAt.replace(/[-:.TZ]/g, "").slice(0, 14)}_${shortHash(`${repositoryId}:${diffHash}:${randomUUID()}`)}`;
  const priorityPlan = prioritizeFindings(options.report.findings);
  const priorityByFindingKey = new Map(priorityPlan.orderedFindings.map((finding) => [finding.key, finding.priority]));
  const manifest: AuditManifest = {
    auditRunId,
    repository: {
      id: repositoryId,
      name: repositoryName,
      root: options.repoDiff.repoRoot,
      remoteUrl: repoMetadata.remoteUrl,
      branch: snapshotBranch,
      commitSha: snapshotCommitSha
    },
    diffHash,
    engineVersion,
    engineCommit,
    rulePackId,
    rulePackVersion,
    standardsSnapshotHash,
    configHash,
    status: options.report.status,
    startedAt,
    completedAt
  };

  try {
    db.exec("BEGIN");
    seedStandards(db);
    insertRepository(db, {
      id: repositoryId,
      name: repositoryName,
      remoteUrl: repoMetadata.remoteUrl,
      root: options.repoDiff.repoRoot
    });
    run(db, `INSERT OR IGNORE INTO repo_snapshots (
      id, repository_id, commit_sha, branch, diff_hash, tree_hash, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`, [
      repoSnapshotId,
      repositoryId,
      snapshotCommitSha ?? null,
      snapshotBranch ?? null,
      diffHash,
      repoMetadata.treeHash ?? null,
      JSON.stringify({ command: options.repoDiff.command, mode: options.repoDiff.mode, truncated: options.repoDiff.truncated })
    ]);
    insertEdge(db, "repository", repositoryId, "HAS_SNAPSHOT", "repo_snapshot", repoSnapshotId);
    run(db, `INSERT OR IGNORE INTO rule_packs (
      id, version, engine_version, engine_commit, standards_snapshot_hash, config_hash, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`, [
      rulePackId,
      rulePackVersion,
      engineVersion,
      engineCommit ?? null,
      standardsSnapshotHash,
      configHash,
      JSON.stringify({ generatedFrom: "mcp-compliance-scan", reviewRequest: options.reviewRequest })
    ]);

    run(db, `INSERT INTO audit_runs (
      id, repository_id, repo_snapshot_id, rule_pack_id, engine_version, engine_commit,
      config_hash, standards_snapshot_hash, status, started_at, completed_at, summary_json, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
      auditRunId,
      repositoryId,
      repoSnapshotId,
      rulePackId,
      engineVersion,
      engineCommit ?? null,
      configHash,
      standardsSnapshotHash,
      options.report.status,
      startedAt,
      completedAt,
      JSON.stringify({
        summary: options.report.summary,
        counts: options.report.counts,
        priorityCounts: priorityPlan.counts,
        findingCount: options.report.findingCount,
        reviewedFiles: options.report.reviewedFiles
      }),
      JSON.stringify({
        manifest,
        priority: {
          counts: priorityPlan.counts,
          remediationSteps: priorityPlan.remediationSteps.slice(0, 50)
        },
        report: options.report,
        repositoryDiff: {
          command: options.repoDiff.command,
          mode: options.repoDiff.mode,
          truncated: options.repoDiff.truncated,
          diffBytes: Buffer.byteLength(options.repoDiff.diffText, "utf8")
        }
      })
    ]);
    insertEdge(db, "audit_run", auditRunId, "USED_REPO_SNAPSHOT", "repo_snapshot", repoSnapshotId);
    insertEdge(db, "audit_run", auditRunId, "USED_RULE_PACK", "rule_pack", rulePackId);
    insertEdge(db, "audit_run", auditRunId, "USED_STANDARDS_SNAPSHOT", "standards_snapshot", standardsSnapshotHash);

    const findingIds: string[] = [];
    const findingIdByPriorityKey = new Map<string, string>();
    for (const finding of options.report.findings) {
      const ruleId = insertRule(db, rulePackId, finding);
      mapRuleToControls(db, ruleId, finding.standards);
      const key = findingKey(finding);
      const findingId = insertFinding(db, {
        auditRunId,
        ruleId,
        repoSnapshotId,
        finding,
        priority: priorityByFindingKey.get(key)
      });
      mapFindingToControls(db, findingId, finding.standards);
      findingIds.push(findingId);
      findingIdByPriorityKey.set(key, findingId);
    }
    insertPriorityGraphEdges(db, priorityPlan, findingIdByPriorityKey);

    db.exec("COMMIT");
    return {
      auditRunId,
      dbPath,
      repositoryId,
      repoSnapshotId,
      rulePackId,
      manifest,
      findingIds
    };
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  } finally {
    db.close();
  }
}

export function listAuditRuns(options: AuditDatabaseOptions & { limit?: number } = {}): { dbPath: string; auditRuns: AuditRunSummary[] } {
  const dbPath = resolveAuditDbPath(options.dbPath);
  const db = openDatabase(dbPath, false);

  try {
    const rows = all(db, `SELECT
      ar.id,
      ar.status,
      ar.started_at AS startedAt,
      ar.completed_at AS completedAt,
      ar.engine_version AS engineVersion,
      ar.engine_commit AS engineCommit,
      ar.summary_json AS summaryJson,
      r.name AS repositoryName,
      r.remote_url AS repositoryRemoteUrl,
      SUM(CASE WHEN f.severity = 'blocker' THEN 1 ELSE 0 END) AS blockerCount,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS highCount,
      SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS mediumCount,
      SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS lowCount,
      COUNT(f.id) AS findingCount
    FROM audit_runs ar
    LEFT JOIN repositories r ON r.id = ar.repository_id
    LEFT JOIN findings f ON f.audit_run_id = ar.id
    GROUP BY ar.id
    ORDER BY ar.started_at DESC
    LIMIT ?`, [options.limit ?? 20]);

    return {
      dbPath,
      auditRuns: rows.map(rowToAuditRunSummary)
    };
  } finally {
    db.close();
  }
}

export function getAuditRun(options: AuditDatabaseOptions & { auditRunId: string }): { dbPath: string; auditRun?: AuditRunDetail } {
  const dbPath = resolveAuditDbPath(options.dbPath);
  const db = openDatabase(dbPath, false);

  try {
    const row = get(db, `SELECT
      ar.id,
      ar.status,
      ar.started_at AS startedAt,
      ar.completed_at AS completedAt,
      ar.engine_version AS engineVersion,
      ar.engine_commit AS engineCommit,
      ar.summary_json AS summaryJson,
      ar.metadata_json AS metadataJson,
      r.name AS repositoryName,
      r.remote_url AS repositoryRemoteUrl,
      SUM(CASE WHEN f.severity = 'blocker' THEN 1 ELSE 0 END) AS blockerCount,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS highCount,
      SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS mediumCount,
      SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS lowCount,
      COUNT(f.id) AS findingCount
    FROM audit_runs ar
    LEFT JOIN repositories r ON r.id = ar.repository_id
    LEFT JOIN findings f ON f.audit_run_id = ar.id
    WHERE ar.id = ?
    GROUP BY ar.id`, [options.auditRunId]);

    if (!row) {
      return { dbPath };
    }

    const findings = all(db, `SELECT
      id, rule_key AS ruleKey, severity, status, file_path AS filePath, line_number AS lineNumber,
      title, evidence_preview AS evidencePreview, remediation, confidence, fingerprint, metadata_json AS metadataJson
    FROM findings
    WHERE audit_run_id = ?
    ORDER BY
      CASE severity WHEN 'blocker' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
      file_path ASC,
      line_number ASC`, [options.auditRunId]);

    const controlsByFinding = new Map<string, StandardReference[]>();
    const controlRows = all(db, `SELECT
      fc.finding_id AS findingId,
      sv.standard_source_id AS standardId,
      c.control_key AS control,
      c.title,
      sv.source_url AS url
    FROM finding_controls fc
    JOIN controls c ON c.id = fc.control_id
    JOIN standard_versions sv ON sv.id = c.standard_version_id
    WHERE fc.finding_id IN (${findings.map(() => "?").join(",") || "NULL"})`, findings.map((finding) => String(finding.id)));

    for (const control of controlRows) {
      const findingId = String(control.findingId);
      const list = controlsByFinding.get(findingId) ?? [];
      list.push({
        standardId: String(control.standardId),
        control: String(control.control),
        title: String(control.title),
        url: String(control.url)
      });
      controlsByFinding.set(findingId, list);
    }

    const summary = rowToAuditRunSummary(row);
    return {
      dbPath,
      auditRun: {
        ...summary,
        metadata: parseJson(row.metadataJson),
        findings: findings.map((finding) => {
          const metadata = parseJson(finding.metadataJson) ?? {};
          return {
            id: String(finding.id),
            ruleId: String(finding.ruleKey),
            title: String(finding.title),
            severity: finding.severity as Severity,
            category: String(metadata.category ?? "unknown"),
            file: nullableString(finding.filePath),
            line: nullableNumber(finding.lineNumber),
            evidence: String(finding.evidencePreview ?? ""),
            remediation: String(finding.remediation ?? ""),
            confidence: Number(finding.confidence ?? 0),
            standards: controlsByFinding.get(String(finding.id)) ?? [],
            status: String(finding.status),
            fingerprint: String(finding.fingerprint),
            priority: metadata.priority,
            controls: controlsByFinding.get(String(finding.id)) ?? []
          } as ReviewFinding & { id: string; status: string; fingerprint: string; priority?: FindingPriority; controls: StandardReference[] };
        })
      }
    };
  } finally {
    db.close();
  }
}

export function summarizeAuditTrends(options: AuditDatabaseOptions & { days?: number } = {}): AuditTrends {
  const dbPath = resolveAuditDbPath(options.dbPath);
  const days = options.days ?? 30;
  const db = openDatabase(dbPath, false);

  try {
    const byDayRows = all(db, `SELECT
      substr(ar.started_at, 1, 10) AS day,
      COUNT(DISTINCT ar.id) AS auditRuns,
      SUM(CASE WHEN f.severity = 'blocker' THEN 1 ELSE 0 END) AS blocker,
      SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low,
      COUNT(f.id) AS findings
    FROM audit_runs ar
    LEFT JOIN findings f ON f.audit_run_id = ar.id
    WHERE ar.started_at >= datetime('now', ?)
    GROUP BY substr(ar.started_at, 1, 10)
    ORDER BY day ASC`, [`-${days} days`]);

    const byRuleRows = all(db, `SELECT
      rule_key AS ruleKey,
      SUM(CASE WHEN severity = 'blocker' THEN 1 ELSE 0 END) AS blocker,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low,
      COUNT(id) AS findings
    FROM findings
    WHERE created_at >= datetime('now', ?)
    GROUP BY rule_key
    ORDER BY findings DESC, rule_key ASC
    LIMIT 20`, [`-${days} days`]);

    const totals = byDayRows.reduce<AuditTrends["totals"]>(
      (acc, row) => {
        acc.auditRuns += Number(row.auditRuns ?? 0);
        acc.blocker += Number(row.blocker ?? 0);
        acc.high += Number(row.high ?? 0);
        acc.medium += Number(row.medium ?? 0);
        acc.low += Number(row.low ?? 0);
        acc.findings += Number(row.findings ?? 0);
        return acc;
      },
      { auditRuns: 0, findings: 0, blocker: 0, high: 0, medium: 0, low: 0 }
    );

    return {
      dbPath,
      days,
      generatedAt: new Date().toISOString(),
      totals,
      byDay: byDayRows.map((row) => ({
        day: String(row.day),
        auditRuns: Number(row.auditRuns ?? 0),
        blocker: Number(row.blocker ?? 0),
        high: Number(row.high ?? 0),
        medium: Number(row.medium ?? 0),
        low: Number(row.low ?? 0),
        findings: Number(row.findings ?? 0)
      })),
      byRule: byRuleRows.map((row) => ({
        ruleKey: String(row.ruleKey),
        blocker: Number(row.blocker ?? 0),
        high: Number(row.high ?? 0),
        medium: Number(row.medium ?? 0),
        low: Number(row.low ?? 0),
        findings: Number(row.findings ?? 0)
      }))
    };
  } finally {
    db.close();
  }
}

export function formatAuditHistoryMarkdown(result: { dbPath: string; auditRuns: AuditRunSummary[] }): string {
  const lines = [
    "# Audit History",
    "",
    `Database: ${result.dbPath}`,
    "",
    "| Audit Run | Repository | Status | Started | Findings |",
    "| --- | --- | --- | --- | --- |"
  ];

  for (const run of result.auditRuns) {
    lines.push(`| ${run.id} | ${run.repositoryName ?? "unknown"} | ${run.status} | ${run.startedAt} | ${run.findingCount} (${run.blockerCount}/${run.highCount}/${run.mediumCount}/${run.lowCount}) |`);
  }

  return `${lines.join("\n")}\n`;
}

export function formatAuditTrendsMarkdown(trends: AuditTrends): string {
  const lines = [
    "# Audit Trends",
    "",
    `Database: ${trends.dbPath}`,
    `Window: ${trends.days} days`,
    `Totals: ${trends.totals.auditRuns} audit run(s), ${trends.totals.findings} finding(s)`,
    "",
    "## By Day",
    "",
    "| Day | Runs | Findings | Blocker | High | Medium | Low |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"
  ];

  for (const day of trends.byDay) {
    lines.push(`| ${day.day} | ${day.auditRuns} | ${day.findings} | ${day.blocker} | ${day.high} | ${day.medium} | ${day.low} |`);
  }

  lines.push("", "## By Rule", "", "| Rule | Findings | Blocker | High | Medium | Low |", "| --- | ---: | ---: | ---: | ---: | ---: |");
  for (const rule of trends.byRule) {
    lines.push(`| ${rule.ruleKey} | ${rule.findings} | ${rule.blocker} | ${rule.high} | ${rule.medium} | ${rule.low} |`);
  }

  return `${lines.join("\n")}\n`;
}

function resolveAuditDbPath(dbPath?: string): string {
  return path.resolve(dbPath ?? defaultAuditDbPath());
}

function openDatabase(dbPath: string, create = true): DatabaseSync {
  if (!create && !existsSync(dbPath)) {
    throw new Error(`Audit database does not exist: ${dbPath}. Run init_audit_db first.`);
  }

  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA foreign_keys = ON");
  return db;
}

function seedStandards(db: DatabaseSync): void {
  for (const standard of STANDARDS_CATALOG) {
    const standardVersionId = standardVersionIdFor(standard.id, standard.version);
    run(db, `INSERT OR IGNORE INTO standard_sources (
      id, name, authority, canonical_url, domains_json
    ) VALUES (?, ?, ?, ?, ?)`, [
      standard.id,
      standard.name,
      standard.authority,
      standard.url,
      JSON.stringify(standard.domains)
    ]);
    run(db, `INSERT OR IGNORE INTO standard_versions (
      id, standard_source_id, version, source_url, content_hash, fetched_at, parser_version, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
      standardVersionId,
      standard.id,
      standard.version,
      standard.url,
      sha256(JSON.stringify(standard)),
      new Date().toISOString(),
      "standards-catalog-v1",
      JSON.stringify({ summary: standard.summary })
    ]);
  }

  for (const reference of allKnownReferences()) {
    insertControl(db, reference);
  }
}

function insertRepository(db: DatabaseSync, repository: { id: string; name: string; remoteUrl?: string; root: string }): void {
  run(db, `INSERT INTO repositories (id, name, remote_url, visibility, metadata_json)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      remote_url = excluded.remote_url,
      metadata_json = excluded.metadata_json`, [
    repository.id,
    repository.name,
    repository.remoteUrl ?? null,
    repository.remoteUrl?.includes("github.com") ? "unknown" : null,
    JSON.stringify({ root: repository.root })
  ]);
}

function insertRule(db: DatabaseSync, rulePackId: string, finding: ReviewFinding): string {
  const ruleId = `rule_${shortHash(`${rulePackId}:${finding.ruleId}`)}`;
  run(db, `INSERT OR IGNORE INTO rules (
    id, rule_pack_id, rule_key, title, category, default_severity, matcher_hash, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, [
    ruleId,
    rulePackId,
    finding.ruleId,
    finding.title,
    finding.category,
    finding.severity,
    shortHash(finding.ruleId),
    JSON.stringify({ source: "reviewDiff" })
  ]);
  insertEdge(db, "rule_pack", rulePackId, "CONTAINS_RULE", "rule", ruleId);
  return ruleId;
}

function insertFinding(db: DatabaseSync, options: {
  auditRunId: string;
  ruleId: string;
  repoSnapshotId: string;
  finding: ReviewFinding;
  priority?: FindingPriority;
}): string {
  const fingerprint = findingFingerprint(options.finding);
  const findingId = `finding_${shortHash(`${options.auditRunId}:${fingerprint}`)}`;

  run(db, `INSERT INTO findings (
    id, audit_run_id, rule_id, rule_key, severity, status, file_path, line_number,
    title, evidence_hash, evidence_preview, remediation, confidence, fingerprint,
    introduced_in_snapshot_id, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [
    findingId,
    options.auditRunId,
    options.ruleId,
    options.finding.ruleId,
    options.finding.severity,
    "open",
    options.finding.file ?? null,
    options.finding.line ?? null,
    options.finding.title,
    sha256(options.finding.evidence),
    options.finding.evidence.slice(0, 500),
    options.finding.remediation,
    options.finding.confidence,
    fingerprint,
    options.repoSnapshotId,
    JSON.stringify({
      category: options.finding.category,
      priority: options.priority,
      standards: options.finding.standards
    })
  ]);
  insertEdge(db, "audit_run", options.auditRunId, "HAS_FINDING", "finding", findingId);
  insertEdge(db, "finding", findingId, "PRODUCED_BY_RULE", "rule", options.ruleId);

  return findingId;
}

function insertPriorityGraphEdges(db: DatabaseSync, priorityPlan: ReturnType<typeof prioritizeFindings>, findingIdByPriorityKey: Map<string, string>): void {
  for (const edge of priorityPlan.graph.edges) {
    const fromFindingId = findingIdByPriorityKey.get(edge.from);
    if (!fromFindingId || edge.type === "VIOLATES_CONTROL") {
      continue;
    }

    const toFindingId = findingIdByPriorityKey.get(edge.to);
    if (toFindingId) {
      insertEdge(db, "finding", fromFindingId, edge.type, "finding", toFindingId, {
        rationale: edge.rationale,
        weight: edge.weight,
        ...edge.metadata
      });
      continue;
    }

    if (edge.type === "AFFECTS_COMPONENT") {
      insertEdge(db, "finding", fromFindingId, edge.type, "component", edge.to, {
        rationale: edge.rationale,
        weight: edge.weight,
        ...edge.metadata
      });
    }
  }
}

function insertControl(db: DatabaseSync, reference: StandardReference): string {
  const standard = STANDARDS_CATALOG.find((candidate) => candidate.id === reference.standardId);
  const standardVersionId = standardVersionIdFor(reference.standardId, standard?.version ?? "unknown");
  const controlId = controlIdFor(reference);

  run(db, `INSERT OR IGNORE INTO controls (
    id, standard_version_id, control_key, title, body_hash, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?)`, [
    controlId,
    standardVersionId,
    reference.control,
    reference.title,
    sha256(reference.title),
    JSON.stringify({ url: reference.url })
  ]);
  insertEdge(db, "standard_version", standardVersionId, "CONTAINS_CONTROL", "control", controlId);
  return controlId;
}

function mapRuleToControls(db: DatabaseSync, ruleId: string, references: StandardReference[]): void {
  for (const reference of references) {
    const controlId = insertControl(db, reference);
    run(db, `INSERT OR IGNORE INTO rule_control_mappings (
      id, rule_id, control_id, mapping_type, confidence
    ) VALUES (?, ?, ?, ?, ?)`, [
      `mapping_${shortHash(`${ruleId}:${controlId}`)}`,
      ruleId,
      controlId,
      "supports",
      1.0
    ]);
    insertEdge(db, "rule", ruleId, "MAPS_TO_CONTROL", "control", controlId);
  }
}

function mapFindingToControls(db: DatabaseSync, findingId: string, references: StandardReference[]): void {
  for (const reference of references) {
    const controlId = insertControl(db, reference);
    run(db, "INSERT OR IGNORE INTO finding_controls (finding_id, control_id) VALUES (?, ?)", [
      findingId,
      controlId
    ]);
    insertEdge(db, "finding", findingId, "VIOLATES_CONTROL", "control", controlId);
  }
}

function insertEdge(db: DatabaseSync, fromType: string, fromId: string, edgeType: string, toType: string, toId: string, metadata: Record<string, unknown> = {}): void {
  run(db, `INSERT OR IGNORE INTO graph_edges (
    id, from_type, from_id, edge_type, to_type, to_id, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?)`, [
    `edge_${shortHash(`${fromType}:${fromId}:${edgeType}:${toType}:${toId}`)}`,
    fromType,
    fromId,
    edgeType,
    toType,
    toId,
    JSON.stringify(metadata)
  ]);
}

function rowToAuditRunSummary(row: Record<string, unknown>): AuditRunSummary {
  return {
    id: String(row.id),
    repositoryName: nullableString(row.repositoryName),
    repositoryRemoteUrl: nullableString(row.repositoryRemoteUrl),
    status: row.status as ReviewStatus,
    startedAt: String(row.startedAt),
    completedAt: nullableString(row.completedAt),
    engineVersion: String(row.engineVersion),
    engineCommit: nullableString(row.engineCommit),
    blockerCount: Number(row.blockerCount ?? 0),
    highCount: Number(row.highCount ?? 0),
    mediumCount: Number(row.mediumCount ?? 0),
    lowCount: Number(row.lowCount ?? 0),
    findingCount: Number(row.findingCount ?? 0),
    summary: parseJson(row.summaryJson)
  };
}

function allKnownReferences(): StandardReference[] {
  const references = [
    ...Object.values(CHECKLIST_STANDARD_REFERENCES).flat(),
    ...Object.values(RULE_STANDARD_REFERENCES).flat()
  ];
  const seen = new Set<string>();
  return references.filter((reference) => {
    const key = `${reference.standardId}:${reference.control}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function readRepositoryMetadata(repoRoot: string): { remoteUrl?: string; branch?: string; commitSha?: string; treeHash?: string } {
  return {
    remoteUrl: gitOutput(repoRoot, ["config", "--get", "remote.origin.url"]),
    branch: gitOutput(repoRoot, ["rev-parse", "--abbrev-ref", "HEAD"]),
    commitSha: gitOutput(repoRoot, ["rev-parse", "HEAD"]),
    treeHash: gitOutput(repoRoot, ["rev-parse", "HEAD^{tree}"])
  };
}

function gitOutput(cwd: string, args: string[]): string | undefined {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined;
  } catch {
    return undefined;
  }
}

function readPackageVersion(): string {
  try {
    const packageJson = JSON.parse(readFileSync(path.join(PACKAGE_ROOT, "package.json"), "utf8"));
    return String(packageJson.version ?? "0.0.0");
  } catch {
    return "0.0.0";
  }
}

function readEngineCommit(): string | undefined {
  return gitOutput(PACKAGE_ROOT, ["rev-parse", "--short", "HEAD"]);
}

function standardsSnapshotHashForCurrentCatalog(): string {
  return sha256(JSON.stringify({
    standards: STANDARDS_CATALOG,
    checklistReferences: CHECKLIST_STANDARD_REFERENCES,
    ruleReferences: RULE_STANDARD_REFERENCES
  }));
}

function repositoryNameFromRemote(remoteUrl: string): string {
  const withoutGit = remoteUrl.replace(/\.git$/i, "");
  const parts = withoutGit.split(/[/:]/).filter(Boolean);
  return parts.slice(-2).join("/");
}

function findingFingerprint(finding: ReviewFinding): string {
  return `fp_${shortHash([
    finding.ruleId,
    finding.file ?? "",
    finding.line ?? "",
    finding.title,
    sha256(finding.evidence)
  ].join("|"))}`;
}

function standardVersionIdFor(standardId: string, version: string): string {
  return `standard_version_${shortHash(`${standardId}:${version}`)}`;
}

function controlIdFor(reference: StandardReference): string {
  return `control_${shortHash(`${reference.standardId}:${reference.control}`)}`;
}

function run(db: DatabaseSync, sql: string, values: SqlValue[] = []): void {
  db.prepare(sql).run(...values);
}

function get(db: DatabaseSync, sql: string, values: SqlValue[] = []): Record<string, unknown> | undefined {
  return db.prepare(sql).get(...values) as Record<string, unknown> | undefined;
}

function all(db: DatabaseSync, sql: string, values: SqlValue[] = []): Array<Record<string, unknown>> {
  return db.prepare(sql).all(...values) as Array<Record<string, unknown>>;
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

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
