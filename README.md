# CloudCord

CloudCord is an AGPL-3.0-or-later, Cloudflare-native community chat platform. It is designed for one operator hosting many independent guilds, with a responsive PWA and a Tauri v2 desktop shell.

This repository contains a deployable Cloudflare-native application and working end-to-end product paths. It does not claim complete Discord API compatibility: the compatibility snapshot in [`docs/discord-v10-compatibility.json`](docs/discord-v10-compatibility.json) is the release gate and names every remaining wire-compatibility gap explicitly.

## Implemented foundation

- Node.js 24 npm-workspaces monorepo with shared Zod contracts and BigInt permission evaluation.
- React/Vite installable PWA with registration, email verification, password/TOTP and Passkey login, friends/DMs, guild/channel navigation, ordered chat, Forum posts, server administration, Bot development/install, camera, screen-share, and voice controls.
- Hono Worker with encrypted identity fields, Argon2id, mandatory TOTP, TOTP replay defense, passkeys with user verification, rotating refresh tokens, reuse detection, one-time administrator bootstrap, friends, blocks, DM/group membership, guilds, all declared channel types, scheduled events, R2 upload authorization, and Cloudflare Realtime session proxying.
- Generation-aware routing across all 16 Social and 32 Guild D1 databases, a resource directory for channel lookup, encrypted idempotency replays, and transactional outboxes for email/search/archive delivery.
- Ordered messages with replies, attachments, editing, soft deletion, reactions, pins, and polls; the Japanese/English PWA exposes these operations and receives live update/delete events.
- SQLite Durable Objects for 1,024-shard Snowflake generation, guild coordination, presence, channel ordering, monthly archive/search, user gateways, strongly ordered rate limits, live voice state, and resumable Bot Gateway sessions.
- Discord v10 compatibility routes for core channel/message/guild/member/role/ban/webhook/application-command/interaction resources, JSON Gateway identify/resume and a live-only Node voice adapter. Unsupported v10 surface remains explicitly marked partial.
- Fixed resource manifest for 1 Identity D1, 16 Social D1, 32 Guild D1, R2, KV, Queues, and isolated environment naming.
- Tauri v2 desktop shell with deep links, R2-compatible updater endpoint configuration, and OS credential-store commands.

The live voice path never writes audio or video payloads to D1, Durable Objects, KV, Queues, or R2. Only participant/control state and aggregate duration/track-type/estimated-byte usage metadata are stored.

## Local development

Requirements: Node.js 24, npm 11, Rust 1.95, and a Cloudflare account for testing Realtime.

```powershell
npm.cmd install
Copy-Item apps/worker/.dev.vars.example apps/worker/.dev.vars
npm.cmd run db:migrate:local
npm.cmd run build -w @cloudcord/web
npm.cmd run dev:worker
```

Open `http://localhost:8787`. In local development, registration accepts `local-dev` as the Turnstile value and returns the email verification token in the response. Configure `REALTIME_APP_ID` and `REALTIME_API_TOKEN` to establish actual media sessions.

## Verification

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build -w @cloudcord/web
npm.cmd run worker:dry-run
npm.cmd run test:e2e
```

The browser test requires Playwright Chromium (`npx.cmd playwright install chromium`). Large WebSocket and WebRTC tests are intentionally manual. Start with [`tools/load/websocket-harness.mjs`](tools/load/websocket-harness.mjs) and never describe design targets as measured capacity until staging results exist.

The live media harness requires a JSON array of distinct staging access tokens. It establishes actual Opus tracks, reports connection p95 and aggregate WebRTC byte counters, then closes every peer without writing media payloads:

```powershell
$env:CLOUDCORD_API_BASE="https://staging.example.com/api/v1"
$env:CLOUDCORD_VOICE_CHANNEL_ID="123456789012345678"
$env:CLOUDCORD_ACCESS_TOKENS_FILE="C:\secure\staging-tokens.json"
$env:CLOUDCORD_WEBRTC_PEERS="20"
$env:CLOUDCORD_SOAK_SECONDS="300"
npm.cmd run load:webrtc
```

Increase the harness to 500 peers only in the dedicated staging load window. The repository contains no claimed production capacity result; measurements must be archived separately with the deployment version and Cloudflare account limits.

## Provisioning and deployment

`npm run infra:plan` prints all 55 environment resources without changing Cloudflare. After checking the account and names:

```powershell
node scripts/provision-cloudflare.mjs --env staging --apply
node scripts/provision-cloudflare.mjs --env prod --apply --confirm-production
```

Copy [`infra/inventory.example.json`](infra/inventory.example.json) outside the repository, fill it with the non-secret IDs returned by Cloudflare, and render an environment-specific configuration:

```powershell
npm.cmd run config:render -- --inventory C:\secure\cloudcord-staging.json --output C:\secure\wrangler.staging.json
```

The renderer refuses incomplete 1+16+32 D1 inventories and will not overwrite an existing output. Put secret values in Cloudflare Secrets Store, apply every D1 migration with the rendered config, configure Email Service and Realtime, then deploy. GitHub Actions is limited to checks and three-OS desktop builds; release artifacts are copied to R2.

See [`docs/architecture.md`](docs/architecture.md) and [`docs/security.md`](docs/security.md).

## License

AGPL-3.0-or-later. Network users must be offered the corresponding source under the license terms.
