# ADR-0003: Local OAuth 2.1 authorization server with audience-bound JWTs

## Context
The MCP authorization specification makes the MCP server an OAuth 2.1 **resource server**: it validates access
tokens issued by a separate authorization server, advertised through Protected Resource Metadata (RFC 9728).
The project must run offline with Docker Compose, so a cloud IdP is not an option for the demo, but the design
must be IdP-agnostic.

## Decision
- Ship a small **OAuth 2.1 authorization server** (`securemcp.auth_server`, FastAPI) with: RFC 8414 metadata,
  JWKS, authorization code + **PKCE S256** (mandatory), exact redirect URI matching, resource indicators (RFC 8707),
  pre-registered public clients, synthetic users with PBKDF2 password hashes.
- Issue **RS256 JWT access tokens** (15 minutes) with `aud` = the MCP resource URL and custom claims `tenant_id`,
  `roles`, `client_id`, `scope`.
- The MCP server validates tokens locally with the JWKS (`JwtTokenVerifier`): signature, `alg` pinned to RS256,
  `iss`, `aud`, `exp`, `nbf`, required claims. It also enables the SDK's `validate_token_resource`.

## Alternatives considered
- **Keycloak in Compose**: realistic, but heavy (memory, startup time, realm export) and hides the mechanics this
  project exists to teach.
- **Opaque tokens + introspection**: instant revocation, but a network call per request and a hard dependency.
- **Dynamic Client Registration**: required for arbitrary third-party MCP clients; unnecessary for a closed
  enterprise deployment where clients are known, and it widens the attack surface.
- **Static API keys**: no delegation, no user identity, no scopes.

## Consequences
- Swapping in a real IdP only requires changing `SECUREMCP_AUTH_ISSUER`, `SECUREMCP_AUTH_JWKS_URL` and the claim
  mapping.
- Revocation is by expiry (15 min). Refresh tokens are not implemented; the host logs in again.
