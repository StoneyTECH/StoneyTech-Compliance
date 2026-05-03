-- Local compliance audit ledger schema.
-- This schema is public-safe. Actual SQLite database files are local-only and ignored.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS standard_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  authority TEXT NOT NULL,
  canonical_url TEXT NOT NULL,
  domains_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS standard_versions (
  id TEXT PRIMARY KEY,
  standard_source_id TEXT NOT NULL REFERENCES standard_sources(id),
  version TEXT NOT NULL,
  source_url TEXT NOT NULL,
  content_hash TEXT,
  fetched_at TEXT,
  parser_version TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (standard_source_id, version)
);

CREATE TABLE IF NOT EXISTS controls (
  id TEXT PRIMARY KEY,
  standard_version_id TEXT NOT NULL REFERENCES standard_versions(id),
  control_key TEXT NOT NULL,
  title TEXT NOT NULL,
  body_hash TEXT,
  parent_control_id TEXT REFERENCES controls(id),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE (standard_version_id, control_key)
);

CREATE TABLE IF NOT EXISTS rule_packs (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  engine_commit TEXT,
  standards_snapshot_hash TEXT NOT NULL,
  config_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  rule_pack_id TEXT NOT NULL REFERENCES rule_packs(id),
  rule_key TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  default_severity TEXT NOT NULL CHECK (default_severity IN ('blocker', 'high', 'medium', 'low')),
  matcher_hash TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE (rule_pack_id, rule_key)
);

CREATE TABLE IF NOT EXISTS rule_control_mappings (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL REFERENCES rules(id),
  control_id TEXT NOT NULL REFERENCES controls(id),
  mapping_type TEXT NOT NULL DEFAULT 'supports',
  confidence REAL NOT NULL DEFAULT 1.0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (rule_id, control_id, mapping_type)
);

CREATE TABLE IF NOT EXISTS repositories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  remote_url TEXT,
  visibility TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS repository_policies (
  repository_id TEXT PRIMARY KEY REFERENCES repositories(id),
  track_merges INTEGER NOT NULL DEFAULT 1,
  tracked_branches_json TEXT NOT NULL DEFAULT '[]',
  risk_tier TEXT NOT NULL DEFAULT 'tier_2' CHECK (risk_tier IN ('tier_1', 'tier_2', 'tier_3', 'inventory_only')),
  scan_profile TEXT NOT NULL DEFAULT 'security' CHECK (scan_profile IN ('standard', 'strict', 'security')),
  local_path TEXT,
  last_merge_sync_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS github_sync_state (
  id TEXT PRIMARY KEY,
  cursor TEXT,
  synced_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS repo_snapshots (
  id TEXT PRIMARY KEY,
  repository_id TEXT NOT NULL REFERENCES repositories(id),
  commit_sha TEXT,
  branch TEXT,
  diff_hash TEXT NOT NULL,
  tree_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_runs (
  id TEXT PRIMARY KEY,
  repository_id TEXT REFERENCES repositories(id),
  repo_snapshot_id TEXT REFERENCES repo_snapshots(id),
  rule_pack_id TEXT REFERENCES rule_packs(id),
  engine_version TEXT NOT NULL,
  engine_commit TEXT,
  config_hash TEXT,
  standards_snapshot_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pass', 'warn', 'fail', 'error')),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  summary_json TEXT NOT NULL DEFAULT '{}',
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS merge_events (
  id TEXT PRIMARY KEY,
  repository_id TEXT NOT NULL REFERENCES repositories(id),
  provider TEXT NOT NULL DEFAULT 'github',
  provider_event_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('pull_request_merged', 'default_branch_commit')),
  branch TEXT NOT NULL,
  base_sha TEXT,
  head_sha TEXT,
  merge_commit_sha TEXT NOT NULL,
  pr_number INTEGER,
  title TEXT,
  author TEXT,
  merged_at TEXT NOT NULL,
  html_url TEXT,
  audit_run_id TEXT REFERENCES audit_runs(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'audited', 'skipped', 'error')),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (provider, provider_event_id)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  audit_run_id TEXT NOT NULL REFERENCES audit_runs(id),
  rule_id TEXT REFERENCES rules(id),
  rule_key TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('blocker', 'high', 'medium', 'low')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'waived', 'false_positive')),
  file_path TEXT,
  line_number INTEGER,
  title TEXT NOT NULL,
  evidence_hash TEXT,
  evidence_preview TEXT,
  remediation TEXT,
  confidence REAL NOT NULL,
  fingerprint TEXT NOT NULL,
  introduced_in_snapshot_id TEXT REFERENCES repo_snapshots(id),
  resolved_in_snapshot_id TEXT REFERENCES repo_snapshots(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS finding_controls (
  finding_id TEXT NOT NULL REFERENCES findings(id),
  control_id TEXT NOT NULL REFERENCES controls(id),
  PRIMARY KEY (finding_id, control_id)
);

CREATE TABLE IF NOT EXISTS waivers (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  reason TEXT NOT NULL,
  approved_by TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS remediations (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  action TEXT NOT NULL,
  commit_sha TEXT,
  actor TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id TEXT PRIMARY KEY,
  from_type TEXT NOT NULL,
  from_id TEXT NOT NULL,
  edge_type TEXT NOT NULL,
  to_type TEXT NOT NULL,
  to_id TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (from_type, from_id, edge_type, to_type, to_id)
);

CREATE INDEX IF NOT EXISTS idx_standard_versions_source ON standard_versions(standard_source_id);
CREATE INDEX IF NOT EXISTS idx_controls_standard_version ON controls(standard_version_id);
CREATE INDEX IF NOT EXISTS idx_audit_runs_repo ON audit_runs(repository_id, started_at);
CREATE INDEX IF NOT EXISTS idx_merge_events_repo ON merge_events(repository_id, merged_at);
CREATE INDEX IF NOT EXISTS idx_merge_events_status ON merge_events(status, merged_at);
CREATE INDEX IF NOT EXISTS idx_findings_audit_run ON findings(audit_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings(status, severity);
CREATE INDEX IF NOT EXISTS idx_graph_edges_from ON graph_edges(from_type, from_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_to ON graph_edges(to_type, to_id, edge_type);

INSERT OR IGNORE INTO schema_migrations(version) VALUES ('001_audit_ledger');
INSERT OR IGNORE INTO schema_migrations(version) VALUES ('002_merge_events');
