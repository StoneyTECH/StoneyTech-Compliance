# Security Policy

MCP Compliance Scan is a local-first security-adjacent tool. Security issues matter here.

## Reportable issues

Please report:

- exposed secrets, credentials, or tokens
- missing or bypassable allowed-root validation
- unsafe git ref handling or shell injection paths
- public-boundary leaks that expose private repository data or local audit contents
- MCP surfaces that widen tool authority unexpectedly

## Not in scope

- policy disagreements that do not create a security boundary failure
- standards-catalog version drift by itself
- local workflow setup mistakes outside this repository

## Reporting

Use a private GitHub security advisory for sensitive issues. Do not publish live credentials, private repository details, or exploit instructions in public issues.

## Operating assumption

This repository should remain safe to publish because it contains:

- code
- schemas
- docs
- sanitized workflow templates

It should not contain:

- populated audit ledgers
- repository clone caches
- local scheduler runtime state
- real credentials or tokens
