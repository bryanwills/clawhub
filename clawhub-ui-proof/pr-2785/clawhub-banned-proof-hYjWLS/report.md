# ClawHub UI Proof

Status: pass

- Scenario: local-auth malicious skill auto-ban flow
- Route verified: /account-banned
- Assertions: banned sign-in redirects to the ban page, email guidance is visible, and the appeal link points to https://appeals.openclaw.ai/.
- Command: PLAYWRIGHT_LOCAL_AUTH_CONVEX_URL=http://127.0.0.1:3220 PLAYWRIGHT_LOCAL_AUTH_CONVEX_SITE_URL=http://127.0.0.1:3221 bun run test:pw:local-auth -- --project=chromium e2e/local-auth/malicious-skill-ban-flow.pw.test.ts
