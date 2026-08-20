# Cyber Shield AI

> AI-assisted threat intelligence and security analysis for suspicious URLs, domains, IP addresses, emails and messages.

Cyber Shield AI combines deterministic security heuristics with live technical intelligence and Gemini-assisted analysis. It is designed as a defensive analysis console: submit a suspicious artifact, inspect the evidence, understand the risk, and make a safer decision.

## Highlights

- **Threat scoring** with Safe / Suspicious / Phishing / Malicious classifications.
- **Technical intelligence** from DNS, TLS certificates and WHOIS where available.
- **Defensive heuristics** for suspicious TLDs, URL shorteners, Punycode and target entropy.
- **AI-assisted reasoning** with structured JSON output and a deterministic fallback when Gemini is unavailable.
- **Scan history** backed by Firebase for authenticated users.
- **QR scanning and browser-extension workflows** for practical investigation.
- **Dual deployment model**: full Express intelligence locally/server-side and a client-side heuristic fallback for static hosting.

## Architecture

```text
React + Vite
    │
    ├── Analysis UI / Scan History / QR Scanner
    │
    └── POST /api/analyze
             │
             ├── Input validation + rate limit
             ├── DNS resolution + SSRF checks
             ├── TLS certificate inspection
             ├── WHOIS lookup
             ├── Deterministic heuristics
             └── Gemini threat assessment
                      │
                      └── Structured analysis result
```

The browser never receives the Gemini API key. The Express service performs privileged intelligence lookups and returns the analysis result. When the API is unavailable, the application can fall back to local heuristics rather than presenting a broken empty state.

## Security model

Because users may submit attacker-controlled content, Cyber Shield AI treats targets and external intelligence as untrusted data.

The server includes:

- 64 KB JSON request limit.
- 2,048-character target limit.
- Per-client request throttling.
- Configurable CORS allowlist through `CORS_ORIGINS`.
- Protection against common private/reserved IPv4 SSRF targets.
- DNS result validation before server-side TLS inspection.
- Explicit prompt-injection resistance in the Gemini analysis prompt.
- Generic failure responses that avoid leaking internal implementation details.

See [`security_spec.md`](./security_spec.md) for the security requirements and abuse cases.

## Local development

### Prerequisites

- Node.js 20+
- npm
- A Gemini API key for AI-assisted analysis
- Firebase configuration if authentication/history features are enabled

### Install

```bash
npm install
```

Create `.env.local` or `.env` with:

```env
GEMINI_API_KEY=your_gemini_api_key
CORS_ORIGINS=http://localhost:3000
```

For local development, `CORS_ORIGINS` may be omitted. In production, explicitly configure allowed origins.

### Run

```bash
npm run dev
```

The development server starts the Express API and Vite middleware together.

### Validate and build

```bash
npm run typecheck
npm run lint
npm run build
```

## Production deployment

The production build creates the Vite application in `docs/` and bundles the Express server into `dist/server.js`.

For a server deployment:

```bash
npm run build
NODE_ENV=production GEMINI_API_KEY=... CORS_ORIGINS=https://your-domain.example npm start
```

For GitHub Pages or another static host, only the client-side application is available. Server-only DNS/TLS/WHOIS and Gemini features require an externally hosted Express API; the UI can use its heuristic fallback when the API is unreachable.

## Browser extension

The extension source is under [`extension/`](./extension) and the packaged static copy is published under [`public/extension/`](./public/extension). The extension can send the current page or selected content into the Cyber Shield analysis workflow.

## Project structure

```text
src/
  App.tsx                 Main application experience
  components/             Authentication and scan-history UI
  lib/                    Firebase integration
server.ts                 Express intelligence API
extension/                Browser extension source
public/extension/         Static extension assets
docs/                     Production/static build output
firestore.rules           Firebase authorization rules
security_spec.md          Security requirements and abuse cases
```

## Responsible use

This project is intended for defensive security analysis, education and authorized investigations. Do not use it to probe systems you do not own or have permission to assess. Automated intelligence can be incomplete or wrong; treat the result as decision support rather than a definitive security verdict.

## License

The repository currently does not declare a project-specific license. Add an explicit license before distributing the software as an open-source package.
