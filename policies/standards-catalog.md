# Standards Catalog

The compliance engine uses public, recognized standards as review anchors. The deterministic rules should map to at least one source whenever possible.

## Primary Standards

- OWASP ASVS 5.0.0: application, API, web frontend, OAuth/OIDC, data protection, logging, and secure communication requirements.
- OWASP API Security Top 10 2023: API risk prioritization.
- OWASP Top 10 2025: web application risk awareness.
- OWASP REST Security Cheat Sheet: REST implementation guidance.
- NIST SSDF SP 800-218 v1.1: secure software development process controls.
- MITRE CWE Top 25 2025: code-level weakness identifiers.
- OpenSSF SLSA 1.2: source, build, provenance, and artifact integrity.
- OpenSSF Scorecard: repository and dependency security posture checks.
- IETF RFC 9700: OAuth 2.0 security best current practice.
- Model Context Protocol authorization and security guidance: MCP-specific authorization, token, session, and confused-deputy controls.

## Domain Mapping

- MCP: MCP Security Best Practices, MCP Authorization Specification, RFC 9700, OWASP ASVS V10.
- API: OWASP ASVS V4/V8/V10/V16, OWASP API Top 10 2023, OWASP REST Security Cheat Sheet.
- CLI: NIST SSDF, MITRE CWE, OpenSSF Scorecard where repository/process controls apply.
- Web: OWASP ASVS V1/V3/V6/V8/V12/V13/V16, OWASP Top 10 2025.
- OAuth: RFC 9700, OWASP ASVS V10, MCP Authorization Specification for remote MCP transports.
- Supply Chain: NIST SSDF, OpenSSF SLSA, OpenSSF Scorecard.
