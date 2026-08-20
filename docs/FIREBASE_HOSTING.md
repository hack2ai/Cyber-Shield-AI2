# Firebase Hosting deployment

The Vite frontend is built into `docs/`, which is the Firebase Hosting public directory. The production server bundle is also generated as `dist/server.js` for the Node deployment/smoke-test path and is not published by Firebase Hosting.

## GitHub Actions secret

Create a Firebase service-account JSON credential with the minimum permissions required to deploy this project's Hosting site. Add the complete JSON document as a repository or production-environment secret named:

`FIREBASE_SERVICE_ACCOUNT`

The deploy workflow uses that secret only during the deployment job and deletes the temporary credential file afterward.

## Deployment behavior

Every push to `main` triggers `.github/workflows/firebase-hosting.yml`. The workflow installs dependencies, runs the production build, and deploys only Firebase Hosting for project `gen-lang-client-0121845763`.

The workflow also supports manual `workflow_dispatch` runs.

## Local deployment

After authenticating with Firebase CLI, the equivalent local flow is:

```bash
npm install --legacy-peer-deps
npm run build
npx firebase-tools deploy --only hosting --project gen-lang-client-0121845763
```
