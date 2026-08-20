# Firebase Hosting verification

The Vite build writes the frontend to `docs/`. The Firebase Hosting workflow verifies `docs/index.html` before deploying and checks the live Hosting URL after deployment so a Firebase default 404 cannot be reported as a successful deployment.
