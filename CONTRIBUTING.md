# Contributing to Cyber Shield AI

Thanks for helping improve Cyber Shield AI.

## Development workflow

1. Fork or create a feature branch from `main`.
2. Keep changes focused and explain security-sensitive decisions in the PR description.
3. Never commit API keys, Firebase credentials, tokens, cookies, or other secrets.
4. Add or update tests when behavior changes.
5. Run the local validation suite before opening a PR:

```bash
npm run typecheck
npm test
npm run build
```

## Security-sensitive changes

Changes involving URL fetching, DNS, TLS, WHOIS, CORS, authentication, browser-extension permissions, prompts, or CI workflows should include a short threat-model explanation and regression coverage where practical.

Treat all user-supplied targets and external intelligence as untrusted input.

## Pull requests

A good PR should include:

- What changed and why.
- Security or compatibility implications.
- Tests performed.
- Any required environment or deployment changes.

Keep unrelated formatting or refactoring out of focused security fixes.

## Commit hygiene

Use concise, descriptive commit messages such as:

- `feat: add ...`
- `fix: prevent ...`
- `security: harden ...`
- `ci: validate ...`
- `docs: clarify ...`
