# PR #2520 proof

Status: pass

- Rendered the account-ban and artifact-level scanner rejection emails from the real email builders; the account-ban email no longer includes scan-results appeal guidance, while the artifact-level email still includes local scan guidance.
- Captured the dedicated banned-account appeal page from a running local ClawHub preview after `/dashboard?error_description=Account%20banned` redirected to `/account-banned`.
