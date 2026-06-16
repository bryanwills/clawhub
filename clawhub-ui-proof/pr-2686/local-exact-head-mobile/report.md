# ClawHub mobile browse filter UI proof

Exact PR head `aadaa6d7f6ec01797af4444ef36150a251e31270` passed a local full-stack browser scenario at a 390x844 viewport.

## UI scenarios

- Mobile skills browse filters render as separate full-width rows without horizontal overflow.
- Mobile plugin browse filters render as separate full-width rows without horizontal overflow.

## Environment

- Candidate-only feature proof on the isolated PR worktree.
- Local Convex deployment on port 4418 with the exact-head functions pushed.
- Exact-head production build previewed locally and exercised with repository Playwright Chromium.

## Remote proof limitations

- Hetzner proof could not allocate a lease because its configured provider token was invalid.
- AWS Crabbox lease `cbx_dfd7c806be9f` could not install Chromium because Playwright does not support the available `ubuntu26.04-x64` image. The lease was released.
