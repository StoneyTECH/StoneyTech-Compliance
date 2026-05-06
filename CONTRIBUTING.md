# Contributing

Thanks for helping improve MCP Compliance Scan.

## Ground rules

- Keep the project local-first and deterministic.
- Preserve the public-safe boundary. Do not add secrets, live credentials, private repository data, or environment-specific assumptions.
- Prefer explicit policy and standards mappings over vague heuristics.
- Keep MCP surfaces narrow, inspectable, and read-safe by default.

## Development flow

1. Create or switch to a feature branch.
2. Make the smallest change that improves the scanner, policy model, or operator experience.
3. Run the local checks:
   - `npm test`
   - `npm run build`
   - `npm run check:standards:json`
4. Update docs when the CLI, MCP surface, standards catalog, or local-data boundary changes.

## Public boundary

This repository can be public. That means:

- no committed `.env` files
- no populated audit databases
- no local n8n runtime state
- no repository clone caches
- no generated reports containing private repository findings

Keep those in ignored local paths such as `.local/`.

## MCP changes

If you change the MCP surface:

- keep tool scopes explicit
- keep unsafe effects labeled in `mcp_security_policy`
- preserve allowed-root validation and git-ref validation
- update tests for public boundary and security policy behavior

## Standards changes

If you update the standards catalog:

- keep source URLs and version markers explicit
- record whether the source is versioned or tracking
- rerun `npm run check:standards` or `npm run check:standards:json`

## Local orchestrators

`n8n` and GitHub Actions templates belong here only in sanitized form. Add templates and seams, not live operational state.
