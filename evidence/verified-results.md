# Verified Results

## Verification scope

This document records repository-level and CI evidence observed during the professional hardening pass. It is not a formal penetration test, independent security audit, or guarantee that every runtime path is defect-free.

## Security hardening

### Firestore authorization

- User documents are owner-scoped.
- Self-promotion from `user` to `admin` is blocked.
- Scan reports are owner-scoped and immutable after creation.
- Threat scores are constrained to the 0–100 range.
- Scan report classifications are restricted to `Safe`, `Suspicious`, `Phishing`, and `Malicious`.

### API boundary

- Request bodies and targets are size-limited.
- Local hostnames and private/reserved IP addresses are rejected before outbound analysis.
- `/api/analyze` is rate-limited.
- Gemini failures fall back to local defensive heuristics instead of exposing provider errors directly.
- Outbound operations use timeouts.

### Browser extension

- Manifest V3 is used.
- Extension pages use a restrictive CSP.
- The configured API gateway must use HTTPS and cannot contain embedded credentials, query strings, or fragments.
- HTTPS host permission is explicitly declared so configured HTTPS API gateways can be contacted.
- No `<all_urls>` wildcard permission is used.

## Automated verification evidence

The GitHub Actions activity observed during this review shows successful runs on `main` for the latest extension synchronization commit `e28db22`:

```text
CI #261       fix: sync published extension API permissions      ✅
CodeQL #159   fix: sync published extension API permissions      ✅
Firebase Hosting #15   fix: sync published extension API permissions ✅
```

The Firebase Hosting run also completed its frontend build, hosting-output verification, deployment, live-site verification, and service-account cleanup steps successfully.

The CodeQL JavaScript/TypeScript analysis job completed successfully.

## Regression coverage

The repository includes automated tests for:

- Firestore authorization and ownership isolation.
- Scan report integrity, including classification allowlisting and immutability.
- API input validation, local/private target rejection, and rate limiting.
- Browser-extension packaging and manifest consistency across source and published copies.

## Release readiness

The repository is suitable for a professional portfolio/release workflow after the latest successful CI run is retained as evidence and the application is manually exercised in the intended deployment environment.

Do not claim a formal security certification, penetration test, or exhaustive runtime verification from this document alone.
