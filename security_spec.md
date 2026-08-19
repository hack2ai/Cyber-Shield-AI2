# Cyber Shield AI — Security Specification

## Scope

Cyber Shield AI accepts potentially hostile URLs, domains, IP addresses, email addresses and message content. Treat all submitted values and all third-party intelligence as **untrusted data**.

## Data invariants

1. **Users (`/users/{userId}`)**
   - Must be signed in to create/read their own profile.
   - `uid` must match `auth.uid`.
   - `role` cannot be changed by the user.
2. **Scan reports (`/scanReports/{reportId}`)**
   - `userId` must match `auth.uid`.
   - Users can only read their own reports.
   - Reports are immutable after creation.
   - `threatScore` must remain between 0 and 100.
   - Only explicitly supported fields may be written.

## API protections

- JSON request bodies are capped at 64 KB.
- Analysis targets are capped at 2,048 characters.
- Empty or malformed targets are rejected before network lookups.
- CORS should be restricted with `CORS_ORIGINS` in production rather than using a wildcard origin.
- Lightweight per-client rate limiting protects the analysis endpoint from accidental or abusive request floods.
- Server-side URL analysis blocks loopback, private, link-local, multicast, unspecified and reserved IPv4 destinations.
- DNS results are checked before outbound TLS connections to reduce SSRF risk.
- TLS inspection uses a timeout and never treats a certificate as trusted merely because a socket connection succeeded.
- AI prompts explicitly identify submitted content and gathered intelligence as untrusted data and require structured output.
- API keys are read only from server environment variables and are never returned to clients.

## SSRF policy

The analysis service must not become a general-purpose network proxy. Requests resolving to internal or reserved IPv4 address space are rejected. If IPv6 support is added to server-side lookups, equivalent IPv6 loopback, unique-local, link-local, multicast, unspecified and reserved ranges must also be denied.

## Untrusted AI context

Target values, DNS records, WHOIS fields, certificate subjects and other external intelligence may contain attacker-controlled text. These values must be passed to the model as data, never as instructions. The model must return only the expected schema and must not execute, follow or reinterpret instructions embedded in scanned content.

## Abuse cases to test

1. Identity spoofing — create a report using another user's `userId`.
2. Role escalation — update a profile to `role: admin`.
3. Cross-user read — retrieve another user's scan report.
4. Anonymous write — create a report without authentication.
5. Collection scraping — list reports without an authorized user filter.
6. Oversized payload — submit a multi-megabyte target/body.
7. Invalid score — submit `threatScore` outside 0–100.
8. SSRF — analyze `127.0.0.1`, RFC1918 addresses and reserved ranges.
9. DNS rebinding — return a public-looking hostname that resolves to a private address.
10. Prompt injection — submit content containing instructions intended to override the analysis policy.
11. CORS abuse — send cross-origin API requests from an unapproved origin.
12. Rate abuse — flood `/api/analyze` with repeated requests.

## Operational guidance

Use HTTPS in production, rotate Gemini credentials regularly, avoid logging full submitted targets when they may contain personal data, and review Firebase rules whenever report schema or authentication behavior changes.
