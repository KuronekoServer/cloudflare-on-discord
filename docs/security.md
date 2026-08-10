# Security model

- Passwords use Argon2id. TOTP secrets and email addresses use AES-GCM; deterministic lookups use HMAC. TOTP counters prevent immediate replay.
- Passkeys require user verification. Challenges live briefly in Identity D1 and are consumed once.
- Access tokens last 15 minutes. Refresh tokens are hashed, rotate on use, and revoke their entire family when reuse is detected.
- Turnstile protects public registration. The local bypass value is accepted only in the `dev` environment, never staging or production.
- Public authentication attempts and authenticated writes use strongly ordered Durable Object rate-limit buckets. Sensitive recovery/registration, social, upload, message, and general-write scopes have separate limits and return standard reset/retry headers.
- State-changing browser requests validate `Origin` against the configured public origin or the fixed Tauri origins. Credentials remain bearer tokens rather than ambient cookies.
- API responses use CSP and secure headers. Only the configured origin receives credentialed CORS responses.
- Upload declarations are authorized before the body reaches R2; declared size and `Content-Length` must match. Supported image, Ogg, MP3, and PDF types are checked by magic bytes, while unrecognized active-content MIME types are rejected.
- KV never stores sessions, permissions, OTPs, or credentials. Permission decisions must be recomputed from authoritative state for writes.
- IP addresses are not retained directly; sessions hold only a keyed digest.
- Administrative bootstrap is one-time, token-gated, and audited.

Production secrets are required through Cloudflare Secrets Store bindings; classic string fallbacks are development-only. Never commit `.dev.vars`. Rotate the bootstrap token after the first administrator is created.
