-- Rollback for schema/audit-ledger.sql.
-- Drops the local audit ledger objects in reverse dependency order.

PRAGMA foreign_keys = OFF;

DROP TABLE IF EXISTS graph_edges;
DROP TABLE IF EXISTS remediations;
DROP TABLE IF EXISTS waivers;
DROP TABLE IF EXISTS finding_controls;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS merge_events;
DROP TABLE IF EXISTS audit_runs;
DROP TABLE IF EXISTS repo_snapshots;
DROP TABLE IF EXISTS github_sync_state;
DROP TABLE IF EXISTS repository_policies;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS rule_control_mappings;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS rule_packs;
DROP TABLE IF EXISTS controls;
DROP TABLE IF EXISTS standard_versions;
DROP TABLE IF EXISTS standard_sources;
DROP TABLE IF EXISTS schema_migrations;

PRAGMA foreign_keys = ON;
