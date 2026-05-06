import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  cloneOrUpdateRepository,
  fetchRepository,
  getRepositoryExactDiff
} from "./git.js";
import {
  AuditDatabaseOptions,
  initAuditDatabase,
  persistAuditRun
} from "./audit.js";
import { ReviewProfile, formatReviewMarkdown, reviewDiff } from "./review.js";

export type RiskTier = "tier_1" | "tier_2" | "tier_3" | "inventory_only";
export type MergeEventStatus = "pending" | "audited" | "skipped" | "error";
export type MergeEventType = "pull_request_merged" | "default_branch_commit";

export interface RegisteredRepository {
  id: string;
  name: string;
  remoteUrl?: string;
  visibility?: string;
  defaultBranch?: string;
  archived: boolean;
  fork: boolean;
  template: boolean;
  private: boolean;
  trackMerges: boolean;
  trackedBranches: string[];
  riskTier: RiskTier;
  scanProfile: ReviewProfile;
  localPath?: string;
  lastMergeSyncAt?: string;
  metadata: Record<string, unknown>;
}

export interface MergeEvent {
  id: string;
  repositoryId: string;
  repositoryName: string;
  provider: "github";
  providerEventId: string;
  eventType: MergeEventType;
  branch: string;
  baseSha?: string;
  headSha: string;
  mergeCommitSha: string;
  prNumber?: number;
  title?: string;
  author?: string;
  mergedAt: string;
  htmlUrl?: string;
  auditRunId?: string;
  status: MergeEventStatus;
  metadata: Record<string, unknown>;
}

export interface GithubSyncOptions extends AuditDatabaseOptions {
  owner?: string;
  ownerType?: "user" | "org";
  limit?: number;
  includeArchived?: boolean;
  token?: string;
  fetchImpl?: FetchLike;
}

export interface RepositoryMergeSyncOptions extends AuditDatabaseOptions {
  repository: string;
  branch?: string;
  since?: string;
  days?: number;
  limit?: number;
  includeDefaultBranchCommits?: boolean;
  token?: string;
  fetchImpl?: FetchLike;
}

export interface AuditMergeEventOptions extends AuditDatabaseOptions {
  mergeEventId: string;
  repoPath?: string;
  checkoutRoot?: string;
  maxBytes?: number;
  profile?: ReviewProfile;
  language?: string;
  framework?: string;
  riskAreas?: string[];
  maxFindings?: number;
}

export interface AuditUnprocessedMergesOptions extends AuditDatabaseOptions {
  repository?: string;
  checkoutRoot?: string;
  limit?: number;
  maxBytes?: number;
  profile?: ReviewProfile;
  maxFindings?: number;
}

export interface MergeAuditResult {
  dbPath: string;
  mergeEvent: MergeEvent;
  auditRunId: string;
  status: "audited";
  findingCount: number;
}

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
type SqlValue = string | number | null;

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

export async function syncGithubRepositories(options: GithubSyncOptions = {}): Promise<{
  dbPath: string;
  syncedAt: string;
  repositoryCount: number;
  repositories: RegisteredRepository[];
}> {
  const { dbPath, db } = openAuditDatabase(options);
  const syncedAt = new Date().toISOString();
  const client = githubClient(options);
  const endpoint = options.owner
    ? options.ownerType === "org"
      ? `/orgs/${encodeURIComponent(options.owner)}/repos?type=all&sort=updated&direction=desc&per_page=100`
      : `/users/${encodeURIComponent(options.owner)}/repos?type=owner&sort=updated&direction=desc&per_page=100`
    : "/user/repos?visibility=all&affiliation=owner,collaborator,organization_member&sort=updated&direction=desc&per_page=100";

  try {
    const repos = await githubGetAll<GithubRepository>(client, endpoint, options.limit ?? 500);
    const registered: RegisteredRepository[] = [];
    db.exec("BEGIN");
    for (const repo of repos) {
      if (repo.archived && options.includeArchived !== true) {
        upsertRepository(db, repo, syncedAt, false);
      } else {
        registered.push(upsertRepository(db, repo, syncedAt, true));
      }
    }
    run(db, `INSERT INTO github_sync_state (id, cursor, synced_at, metadata_json)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        cursor = excluded.cursor,
        synced_at = excluded.synced_at,
        metadata_json = excluded.metadata_json`, [
      options.owner ? `repos:${options.ownerType ?? "user"}:${options.owner}` : "repos:self",
      null,
      syncedAt,
      JSON.stringify({ repositoryCount: repos.length, includeArchived: options.includeArchived === true })
    ]);
    db.exec("COMMIT");

    return {
      dbPath,
      syncedAt,
      repositoryCount: registered.length,
      repositories: registered.sort((a, b) => a.name.localeCompare(b.name))
    };
  } catch (error) {
    rollbackQuietly(db);
    throw error;
  } finally {
    db.close();
  }
}

export function listRegisteredRepositories(options: AuditDatabaseOptions & {
  limit?: number;
  includeInventoryOnly?: boolean;
} = {}): { dbPath: string; repositories: RegisteredRepository[] } {
  const { dbPath, db } = openAuditDatabase(options);

  try {
    const rows = all(db, `SELECT
      r.id, r.name, r.remote_url AS remoteUrl, r.visibility, r.metadata_json AS repositoryMetadataJson,
      p.track_merges AS trackMerges, p.tracked_branches_json AS trackedBranchesJson,
      p.risk_tier AS riskTier, p.scan_profile AS scanProfile, p.local_path AS localPath,
      p.last_merge_sync_at AS lastMergeSyncAt, p.metadata_json AS policyMetadataJson
    FROM repositories r
    LEFT JOIN repository_policies p ON p.repository_id = r.id
    WHERE (? = 1 OR COALESCE(p.risk_tier, 'tier_2') != 'inventory_only')
    ORDER BY r.name ASC
    LIMIT ?`, [options.includeInventoryOnly === true ? 1 : 0, options.limit ?? 500]);

    return {
      dbPath,
      repositories: rows.map(rowToRegisteredRepository)
    };
  } finally {
    db.close();
  }
}

export async function syncRepositoryMerges(options: RepositoryMergeSyncOptions): Promise<{
  dbPath: string;
  repository: RegisteredRepository;
  branch: string;
  since: string;
  syncedAt: string;
  mergeEventCount: number;
  mergeEvents: MergeEvent[];
}> {
  const { dbPath, db } = openAuditDatabase(options);
  const repository = findRegisteredRepository(db, options.repository);
  const branch = options.branch ?? repository.trackedBranches[0] ?? repository.defaultBranch ?? "main";
  const since = options.since ?? repository.lastMergeSyncAt ?? daysAgoIso(options.days ?? 30);
  const syncedAt = new Date().toISOString();
  const client = githubClient(options);
  const fullName = repository.name;

  try {
    const pullEvents = await fetchMergedPullEvents(client, repository, branch, since, options.limit ?? 100);
    const commitEvents = options.includeDefaultBranchCommits === false
      ? []
      : await fetchDefaultBranchCommitEvents(client, repository, branch, since, options.limit ?? 100, new Set(pullEvents.map((event) => event.mergeCommitSha)));
    const mergeEvents = [...pullEvents, ...commitEvents]
      .sort((a, b) => a.mergedAt.localeCompare(b.mergedAt))
      .slice(0, options.limit ?? 100);

    db.exec("BEGIN");
    for (const event of mergeEvents) {
      upsertMergeEvent(db, event);
    }
    run(db, `UPDATE repository_policies
      SET last_merge_sync_at = ?, updated_at = ?
      WHERE repository_id = ?`, [syncedAt, syncedAt, repository.id]);
    run(db, `INSERT INTO github_sync_state (id, cursor, synced_at, metadata_json)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        cursor = excluded.cursor,
        synced_at = excluded.synced_at,
        metadata_json = excluded.metadata_json`, [
      `merges:${fullName}:${branch}`,
      since,
      syncedAt,
      JSON.stringify({ repositoryId: repository.id, branch, mergeEventCount: mergeEvents.length })
    ]);
    db.exec("COMMIT");

    return {
      dbPath,
      repository,
      branch,
      since,
      syncedAt,
      mergeEventCount: mergeEvents.length,
      mergeEvents
    };
  } catch (error) {
    rollbackQuietly(db);
    throw error;
  } finally {
    db.close();
  }
}

export async function auditMergeEvent(options: AuditMergeEventOptions): Promise<{
  dbPath: string;
  mergeEvent: MergeEvent;
  auditRunId: string;
  repositoryPath: string;
  findingCount: number;
  reviewMarkdown: string;
}> {
  const { dbPath, db } = openAuditDatabase(options);
  const mergeEvent = getMergeEventById(db, options.mergeEventId);
  const repository = findRegisteredRepository(db, mergeEvent.repositoryId);
  const repoPath = await resolveMergeRepositoryPath(repository, options);

  try {
    await fetchRepository(repoPath).catch(() => undefined);
    const baseRef = mergeEvent.baseSha ?? EMPTY_TREE_SHA;
    const repoDiff = await getRepositoryExactDiff({
      repoPath,
      baseRef,
      targetRef: mergeEvent.mergeCommitSha,
      maxBytes: options.maxBytes
    });
    repoDiff.branch = mergeEvent.branch;
    const profile = options.profile ?? repository.scanProfile;
    const report = reviewDiff(repoDiff.diffText, {
      profile,
      maxFindings: options.maxFindings,
      language: options.language,
      framework: options.framework,
      riskAreas: options.riskAreas,
      truncated: repoDiff.truncated
    });
    const persisted = persistAuditRun({
      dbPath,
      repoDiff,
      report,
      reviewRequest: {
        source: "merge_event",
        mergeEventId: mergeEvent.id,
        repository: repository.name,
        branch: mergeEvent.branch,
        baseSha: baseRef,
        mergeCommitSha: mergeEvent.mergeCommitSha,
        profile,
        language: options.language,
        framework: options.framework,
        riskAreas: options.riskAreas
      }
    });

    markMergeEventAudited(db, mergeEvent.id, persisted.auditRunId);
    insertEdge(db, "merge_event", mergeEvent.id, "HAS_AUDIT_RUN", "audit_run", persisted.auditRunId, {
      branch: mergeEvent.branch,
      mergeCommitSha: mergeEvent.mergeCommitSha
    });
    insertEdge(db, "merge_event", mergeEvent.id, "TARGETS_REPOSITORY", "repository", repository.id, {
      repository: repository.name
    });

    return {
      dbPath,
      mergeEvent: {
        ...mergeEvent,
        auditRunId: persisted.auditRunId,
        status: "audited"
      },
      auditRunId: persisted.auditRunId,
      repositoryPath: repoPath,
      findingCount: report.findingCount,
      reviewMarkdown: formatReviewMarkdown(report)
    };
  } catch (error) {
    markMergeEventError(db, mergeEvent.id, error);
    throw error;
  } finally {
    db.close();
  }
}

export async function auditUnprocessedMerges(options: AuditUnprocessedMergesOptions = {}): Promise<{
  dbPath: string;
  processed: MergeAuditResult[];
  errors: Array<{ mergeEventId: string; error: string }>;
}> {
  const { dbPath, db } = openAuditDatabase(options);
  const rows = all(db, `SELECT me.id
    FROM merge_events me
    JOIN repositories r ON r.id = me.repository_id
    WHERE me.status = 'pending'
      AND (? IS NULL OR r.name = ? OR r.id = ?)
    ORDER BY me.merged_at ASC
    LIMIT ?`, [
    options.repository ?? null,
    options.repository ?? null,
    options.repository ?? null,
    options.limit ?? 20
  ]);
  db.close();

  const processed: MergeAuditResult[] = [];
  const errors: Array<{ mergeEventId: string; error: string }> = [];
  for (const row of rows) {
    const mergeEventId = String(row.id);
    try {
      const result = await auditMergeEvent({
        dbPath,
        mergeEventId,
        checkoutRoot: options.checkoutRoot,
        maxBytes: options.maxBytes,
        profile: options.profile,
        maxFindings: options.maxFindings
      });
      processed.push({
        dbPath,
        mergeEvent: result.mergeEvent,
        auditRunId: result.auditRunId,
        status: "audited",
        findingCount: result.findingCount
      });
    } catch (error) {
      errors.push({
        mergeEventId,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  return {
    dbPath,
    processed,
    errors
  };
}

export function mergeAuditHistory(options: AuditDatabaseOptions & {
  repository?: string;
  limit?: number;
} = {}): { dbPath: string; mergeEvents: MergeEvent[] } {
  const { dbPath, db } = openAuditDatabase(options);

  try {
    const rows = all(db, `SELECT
      me.*, r.name AS repositoryName
    FROM merge_events me
    JOIN repositories r ON r.id = me.repository_id
    WHERE (? IS NULL OR r.name = ? OR r.id = ?)
    ORDER BY me.merged_at DESC
    LIMIT ?`, [
      options.repository ?? null,
      options.repository ?? null,
      options.repository ?? null,
      options.limit ?? 50
    ]);

    return {
      dbPath,
      mergeEvents: rows.map(rowToMergeEvent)
    };
  } finally {
    db.close();
  }
}

export function getMergeAudit(options: AuditDatabaseOptions & {
  mergeEventId: string;
}): { dbPath: string; mergeEvent?: MergeEvent } {
  const { dbPath, db } = openAuditDatabase(options);

  try {
    return {
      dbPath,
      mergeEvent: getOptionalMergeEventById(db, options.mergeEventId)
    };
  } finally {
    db.close();
  }
}

export function formatRepositoryListMarkdown(result: { dbPath: string; repositories: RegisteredRepository[] }): string {
  const lines = [
    "# Registered Repositories",
    "",
    `Database: ${result.dbPath}`,
    "",
    "| Repository | Tier | Profile | Branches | Track Merges | Last Sync |",
    "| --- | --- | --- | --- | --- | --- |"
  ];
  for (const repo of result.repositories) {
    const branches = repo.trackedBranches.join(", ") || repo.defaultBranch || "main";
    lines.push(`| ${repo.name} | ${repo.riskTier} | ${repo.scanProfile} | ${branches} | ${repo.trackMerges ? "yes" : "no"} | ${repo.lastMergeSyncAt ?? ""} |`);
  }
  return `${lines.join("\n")}\n`;
}

export function formatMergeHistoryMarkdown(result: { dbPath: string; mergeEvents: MergeEvent[] }): string {
  const lines = [
    "# Merge Audit History",
    "",
    `Database: ${result.dbPath}`,
    "",
    "| Merge Event | Repository | Type | Branch | Merged | Status | Audit Run |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ];
  for (const event of result.mergeEvents) {
    lines.push(`| ${event.id} | ${event.repositoryName} | ${event.eventType} | ${event.branch} | ${event.mergedAt} | ${event.status} | ${event.auditRunId ?? ""} |`);
  }
  return `${lines.join("\n")}\n`;
}

interface GithubRepository {
  id: number;
  name: string;
  full_name: string;
  clone_url?: string;
  html_url?: string;
  private?: boolean;
  visibility?: string;
  archived?: boolean;
  fork?: boolean;
  is_template?: boolean;
  default_branch?: string;
  description?: string | null;
  pushed_at?: string | null;
  updated_at?: string | null;
  topics?: string[];
}

interface GithubPullRequest {
  number: number;
  title?: string;
  html_url?: string;
  merged_at?: string | null;
  merge_commit_sha?: string | null;
  user?: { login?: string };
  base?: { ref?: string; sha?: string };
  head?: { sha?: string };
}

interface GithubCommit {
  sha: string;
  html_url?: string;
  commit?: {
    message?: string;
    author?: { name?: string; date?: string };
    committer?: { name?: string; date?: string };
  };
  author?: { login?: string };
  parents?: Array<{ sha?: string }>;
}

interface GithubClient {
  baseUrl: string;
  fetchImpl: FetchLike;
  headers: Record<string, string>;
}

function openAuditDatabase(options: AuditDatabaseOptions): { dbPath: string; db: DatabaseSync } {
  const init = initAuditDatabase(options);
  const db = new DatabaseSync(init.dbPath);
  db.exec("PRAGMA foreign_keys = ON");
  return { dbPath: init.dbPath, db };
}

function upsertRepository(db: DatabaseSync, repo: GithubRepository, syncedAt: string, trackMerges: boolean): RegisteredRepository {
  const remoteUrl = repo.clone_url ?? repo.html_url ?? `https://github.com/${repo.full_name}.git`;
  const repositoryId = repositoryIdFor(remoteUrl);
  const metadata = {
    githubId: repo.id,
    htmlUrl: repo.html_url,
    defaultBranch: repo.default_branch,
    archived: repo.archived === true,
    fork: repo.fork === true,
    template: repo.is_template === true,
    private: repo.private === true,
    description: repo.description,
    topics: repo.topics ?? [],
    pushedAt: repo.pushed_at,
    updatedAt: repo.updated_at,
    syncedAt
  };
  const riskTier = classifyRiskTier(repo);
  const trackedBranches = repo.default_branch ? [repo.default_branch] : ["main"];
  const scanProfile = riskTier === "tier_1" ? "security" : "standard";

  run(db, `INSERT INTO repositories (id, name, remote_url, visibility, metadata_json)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      remote_url = excluded.remote_url,
      visibility = excluded.visibility,
      metadata_json = excluded.metadata_json`, [
    repositoryId,
    repo.full_name,
    remoteUrl,
    repo.visibility ?? (repo.private ? "private" : "public"),
    JSON.stringify(metadata)
  ]);
  run(db, `INSERT INTO repository_policies (
      repository_id, track_merges, tracked_branches_json, risk_tier, scan_profile, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(repository_id) DO UPDATE SET
      tracked_branches_json = CASE
        WHEN repository_policies.tracked_branches_json = '[]' THEN excluded.tracked_branches_json
        ELSE repository_policies.tracked_branches_json
      END,
      metadata_json = excluded.metadata_json,
      updated_at = ?`, [
    repositoryId,
    trackMerges && riskTier !== "inventory_only" ? 1 : 0,
    JSON.stringify(trackedBranches),
    riskTier,
    scanProfile,
    JSON.stringify({ source: "github", syncedAt }),
    syncedAt
  ]);

  return {
    id: repositoryId,
    name: repo.full_name,
    remoteUrl,
    visibility: repo.visibility ?? (repo.private ? "private" : "public"),
    defaultBranch: repo.default_branch,
    archived: repo.archived === true,
    fork: repo.fork === true,
    template: repo.is_template === true,
    private: repo.private === true,
    trackMerges: trackMerges && riskTier !== "inventory_only",
    trackedBranches,
    riskTier,
    scanProfile,
    metadata
  };
}

async function fetchMergedPullEvents(
  client: GithubClient,
  repository: RegisteredRepository,
  branch: string,
  since: string,
  limit: number
): Promise<MergeEvent[]> {
  const [owner, repo] = splitFullName(repository.name);
  const pulls = await githubGetAll<GithubPullRequest>(
    client,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls?state=closed&base=${encodeURIComponent(branch)}&sort=updated&direction=desc&per_page=100`,
    limit
  );
  const sinceMs = Date.parse(since);

  return pulls
    .filter((pull) => pull.merged_at && Date.parse(pull.merged_at) >= sinceMs)
    .map((pull) => {
      const mergeCommitSha = pull.merge_commit_sha ?? pull.head?.sha;
      if (!mergeCommitSha) {
        throw new Error(`Merged PR ${repository.name}#${pull.number} has no merge commit or head SHA.`);
      }
      return {
        id: mergeEventIdFor(`github:pr:${repository.name}:${pull.number}:${mergeCommitSha}`),
        repositoryId: repository.id,
        repositoryName: repository.name,
        provider: "github",
        providerEventId: `github:pr:${repository.name}:${pull.number}:${mergeCommitSha}`,
        eventType: "pull_request_merged",
        branch: pull.base?.ref ?? branch,
        baseSha: pull.base?.sha,
        headSha: pull.head?.sha ?? mergeCommitSha,
        mergeCommitSha,
        prNumber: pull.number,
        title: pull.title,
        author: pull.user?.login,
        mergedAt: String(pull.merged_at),
        htmlUrl: pull.html_url,
        status: "pending",
        metadata: { source: "github_pulls" }
      } satisfies MergeEvent;
    });
}

async function fetchDefaultBranchCommitEvents(
  client: GithubClient,
  repository: RegisteredRepository,
  branch: string,
  since: string,
  limit: number,
  knownMergeCommits: Set<string>
): Promise<MergeEvent[]> {
  const [owner, repo] = splitFullName(repository.name);
  const commits = await githubGetAll<GithubCommit>(
    client,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits?sha=${encodeURIComponent(branch)}&since=${encodeURIComponent(since)}&per_page=100`,
    limit
  );

  return commits
    .filter((commit) => !knownMergeCommits.has(commit.sha))
    .map((commit) => {
      const providerEventId = `github:commit:${repository.name}:${commit.sha}`;
      const firstParent = commit.parents?.[0]?.sha;
      const title = commit.commit?.message?.split(/\r?\n/)[0] ?? commit.sha;
      return {
        id: mergeEventIdFor(providerEventId),
        repositoryId: repository.id,
        repositoryName: repository.name,
        provider: "github",
        providerEventId,
        eventType: "default_branch_commit",
        branch,
        baseSha: firstParent,
        headSha: commit.sha,
        mergeCommitSha: commit.sha,
        title,
        author: commit.author?.login ?? commit.commit?.author?.name ?? commit.commit?.committer?.name,
        mergedAt: commit.commit?.committer?.date ?? commit.commit?.author?.date ?? new Date().toISOString(),
        htmlUrl: commit.html_url,
        status: "pending",
        metadata: {
          source: "github_commits",
          parentCount: commit.parents?.length ?? 0
        }
      } satisfies MergeEvent;
    });
}

function upsertMergeEvent(db: DatabaseSync, event: MergeEvent): void {
  run(db, `INSERT INTO merge_events (
    id, repository_id, provider, provider_event_id, event_type, branch,
    base_sha, head_sha, merge_commit_sha, pr_number, title, author, merged_at,
    html_url, status, metadata_json
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(provider, provider_event_id) DO UPDATE SET
    repository_id = excluded.repository_id,
    event_type = excluded.event_type,
    branch = excluded.branch,
    base_sha = excluded.base_sha,
    head_sha = excluded.head_sha,
    merge_commit_sha = excluded.merge_commit_sha,
    pr_number = excluded.pr_number,
    title = excluded.title,
    author = excluded.author,
    merged_at = excluded.merged_at,
    html_url = excluded.html_url,
    metadata_json = excluded.metadata_json,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, [
    event.id,
    event.repositoryId,
    event.provider,
    event.providerEventId,
    event.eventType,
    event.branch,
    event.baseSha ?? null,
    event.headSha,
    event.mergeCommitSha,
    event.prNumber ?? null,
    event.title ?? null,
    event.author ?? null,
    event.mergedAt,
    event.htmlUrl ?? null,
    event.status,
    JSON.stringify(event.metadata)
  ]);
  insertEdge(db, "repository", event.repositoryId, "HAS_MERGE_EVENT", "merge_event", event.id, {
    branch: event.branch,
    eventType: event.eventType,
    mergedAt: event.mergedAt
  });
}

async function resolveMergeRepositoryPath(repository: RegisteredRepository, options: AuditMergeEventOptions): Promise<string> {
  if (options.repoPath) {
    return path.resolve(options.repoPath);
  }
  if (repository.localPath) {
    return path.resolve(repository.localPath);
  }
  if (!repository.remoteUrl) {
    throw new Error(`Repository ${repository.name} has no remote URL and no repoPath was provided.`);
  }

  const checkoutRoot = path.resolve(options.checkoutRoot ?? path.join(PACKAGE_ROOT, ".local", "repos"));
  const localPath = path.join(checkoutRoot, repository.name.replace(/[/:]+/g, "__"));
  mkdirSync(checkoutRoot, { recursive: true });
  const repoRoot = await cloneOrUpdateRepository({ remoteUrl: repository.remoteUrl, localPath });
  const { db } = openAuditDatabase(options);
  try {
    run(db, `UPDATE repository_policies SET local_path = ?, updated_at = ? WHERE repository_id = ?`, [
      repoRoot,
      new Date().toISOString(),
      repository.id
    ]);
  } finally {
    db.close();
  }
  return repoRoot;
}

function markMergeEventAudited(db: DatabaseSync, mergeEventId: string, auditRunId: string): void {
  run(db, `UPDATE merge_events
    SET status = 'audited', audit_run_id = ?, updated_at = ?
    WHERE id = ?`, [auditRunId, new Date().toISOString(), mergeEventId]);
}

function markMergeEventError(db: DatabaseSync, mergeEventId: string, error: unknown): void {
  const row = get(db, "SELECT metadata_json AS metadataJson FROM merge_events WHERE id = ?", [mergeEventId]);
  const metadata = parseJson(row?.metadataJson) ?? {};
  run(db, `UPDATE merge_events
    SET status = 'error', metadata_json = ?, updated_at = ?
    WHERE id = ?`, [
    JSON.stringify({
      ...metadata,
      lastError: error instanceof Error ? error.message : String(error)
    }),
    new Date().toISOString(),
    mergeEventId
  ]);
}

function getMergeEventById(db: DatabaseSync, mergeEventId: string): MergeEvent {
  const event = getOptionalMergeEventById(db, mergeEventId);
  if (!event) {
    throw new Error(`Merge event not found: ${mergeEventId}`);
  }
  return event;
}

function getOptionalMergeEventById(db: DatabaseSync, mergeEventId: string): MergeEvent | undefined {
  const row = get(db, `SELECT me.*, r.name AS repositoryName
    FROM merge_events me
    JOIN repositories r ON r.id = me.repository_id
    WHERE me.id = ?`, [mergeEventId]);
  return row ? rowToMergeEvent(row) : undefined;
}

function findRegisteredRepository(db: DatabaseSync, repository: string): RegisteredRepository {
  const row = get(db, `SELECT
      r.id, r.name, r.remote_url AS remoteUrl, r.visibility, r.metadata_json AS repositoryMetadataJson,
      p.track_merges AS trackMerges, p.tracked_branches_json AS trackedBranchesJson,
      p.risk_tier AS riskTier, p.scan_profile AS scanProfile, p.local_path AS localPath,
      p.last_merge_sync_at AS lastMergeSyncAt, p.metadata_json AS policyMetadataJson
    FROM repositories r
    LEFT JOIN repository_policies p ON p.repository_id = r.id
    WHERE r.id = ? OR r.name = ? OR r.remote_url = ?`, [repository, repository, repository]);
  if (!row) {
    throw new Error(`Registered repository not found: ${repository}. Run sync_github_repositories first.`);
  }
  return rowToRegisteredRepository(row);
}

function rowToRegisteredRepository(row: Record<string, unknown>): RegisteredRepository {
  const repositoryMetadata = parseJson(row.repositoryMetadataJson) ?? {};
  const trackedBranches = parseJson(row.trackedBranchesJson);
  return {
    id: String(row.id),
    name: String(row.name),
    remoteUrl: nullableString(row.remoteUrl),
    visibility: nullableString(row.visibility),
    defaultBranch: nullableString(repositoryMetadata.defaultBranch),
    archived: repositoryMetadata.archived === true,
    fork: repositoryMetadata.fork === true,
    template: repositoryMetadata.template === true,
    private: repositoryMetadata.private === true,
    trackMerges: Number(row.trackMerges ?? 1) === 1,
    trackedBranches: Array.isArray(trackedBranches) ? trackedBranches.map(String) : [],
    riskTier: isRiskTier(row.riskTier) ? row.riskTier : "tier_2",
    scanProfile: isReviewProfile(row.scanProfile) ? row.scanProfile : "security",
    localPath: nullableString(row.localPath),
    lastMergeSyncAt: nullableString(row.lastMergeSyncAt),
    metadata: {
      ...repositoryMetadata,
      policy: parseJson(row.policyMetadataJson) ?? {}
    }
  };
}

function rowToMergeEvent(row: Record<string, unknown>): MergeEvent {
  return {
    id: String(row.id),
    repositoryId: String(row.repository_id),
    repositoryName: String(row.repositoryName),
    provider: "github",
    providerEventId: String(row.provider_event_id),
    eventType: row.event_type as MergeEventType,
    branch: String(row.branch),
    baseSha: nullableString(row.base_sha),
    headSha: String(row.head_sha),
    mergeCommitSha: String(row.merge_commit_sha),
    prNumber: nullableNumber(row.pr_number),
    title: nullableString(row.title),
    author: nullableString(row.author),
    mergedAt: String(row.merged_at),
    htmlUrl: nullableString(row.html_url),
    auditRunId: nullableString(row.audit_run_id),
    status: row.status as MergeEventStatus,
    metadata: parseJson(row.metadata_json) ?? {}
  };
}

function githubClient(options: { token?: string; fetchImpl?: FetchLike }): GithubClient {
  const token = options.token
    ?? process.env.MCP_COMPLIANCE_SCAN_GITHUB_TOKEN
    ?? process.env.GITHUB_TOKEN
    ?? process.env.GH_TOKEN
    ?? githubCliToken();
  if (!token) {
    throw new Error("GitHub token required. Set MCP_COMPLIANCE_SCAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN.");
  }
  return {
    baseUrl: "https://api.github.com",
    fetchImpl: options.fetchImpl ?? fetch,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "mcp-compliance-scan",
      "X-GitHub-Api-Version": "2022-11-28"
    }
  };
}

function githubCliToken(): string | undefined {
  try {
    return execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim() || undefined;
  } catch {
    return undefined;
  }
}

async function githubGetAll<T>(client: GithubClient, endpoint: string, limit: number): Promise<T[]> {
  const results: T[] = [];
  let url: string | undefined = `${client.baseUrl}${endpoint}`;

  while (url && results.length < limit) {
    const response = await client.fetchImpl(url, { headers: client.headers });
    if (!response.ok) {
      throw new Error(`GitHub API ${url} failed: ${response.status} ${response.statusText}`);
    }
    const page = await response.json() as T[];
    results.push(...page.slice(0, Math.max(0, limit - results.length)));
    url = nextLink(response.headers.get("link"));
  }

  return results;
}

function nextLink(linkHeader: string | null): string | undefined {
  if (!linkHeader) {
    return undefined;
  }
  for (const part of linkHeader.split(",")) {
    const match = part.match(/<([^>]+)>;\s*rel="next"/);
    if (match?.[1]) {
      return match[1];
    }
  }
  return undefined;
}

function classifyRiskTier(repo: GithubRepository): RiskTier {
  if (repo.archived || repo.fork || repo.is_template) {
    return "inventory_only";
  }
  const text = [
    repo.full_name,
    repo.description,
    ...(repo.topics ?? [])
  ].filter(Boolean).join(" ").toLowerCase();

  if (/\b(auth|oauth|oidc|jwt|api|mcp|worker|infra|terraform|cloudflare|payment|billing|stripe|compliance|security)\b/.test(text)) {
    return "tier_1";
  }

  if (repo.pushed_at && Date.now() - Date.parse(repo.pushed_at) > 1000 * 60 * 60 * 24 * 180) {
    return "tier_3";
  }

  return "tier_2";
}

function splitFullName(fullName: string): [string, string] {
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) {
    throw new Error(`Expected GitHub full name owner/repo, got: ${fullName}`);
  }
  return [owner, repo];
}

function daysAgoIso(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function repositoryIdFor(remoteUrl: string): string {
  return `repo_${shortHash(remoteUrl)}`;
}

function mergeEventIdFor(providerEventId: string): string {
  return `merge_${shortHash(providerEventId)}`;
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

function isRiskTier(value: unknown): value is RiskTier {
  return value === "tier_1" || value === "tier_2" || value === "tier_3" || value === "inventory_only";
}

function isReviewProfile(value: unknown): value is ReviewProfile {
  return value === "standard" || value === "strict" || value === "security";
}

function rollbackQuietly(db: DatabaseSync): void {
  try {
    db.exec("ROLLBACK");
  } catch {
    // No transaction was active.
  }
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
