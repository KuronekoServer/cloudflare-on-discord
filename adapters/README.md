# Bot library adapters

These adapters are pinned compatibility targets, not generic support promises:

- discord.js 14.27.0: use `discordJsAdapter(origin)` from `@cloudcord/bot-adapters` in `new Client({ ...discordJsAdapter(origin), intents })`.
- discord.py 2.7.1: call `cloudcord_adapter.configure(origin)` before constructing the client.
- JDA 6.4.2: wrap the builder with `CloudCordAdapter.configure(builder, origin)`.

All three redirect REST to `/api/v10`; the libraries then discover `/api/v10/gateway` through `/gateway/bot`. Voice connections require the separate Cloudflare Realtime voice adapter because Discord UDP/RTP voice transport is intentionally not exposed.
