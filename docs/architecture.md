# Architecture

CloudCord is a single-operator, multi-guild system whose production runtime is restricted to Cloudflare. The PWA is served through Workers Static Assets. REST and WebSocket requests enter the Worker; durable, ordered, live state is owned by SQLite-backed Durable Objects.

## Data boundaries

| Data                            | Authority                                 | Notes                                                                                        |
| ------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| Identity and credentials        | 1 Identity D1                             | Email and TOTP values are encrypted; lookup values and tokens are hashed                     |
| Relationships and DM membership | 16 Social D1 databases                    | User-keyed indexes plus generation-aware primary/dual-read routing                           |
| Guild configuration             | 32 Guild D1 databases                     | Guild-keyed routing; channel location is resolved through the Identity resource directory    |
| Ordered messages                | ChannelHubDO + monthly MessagePartitionDO | A channel hub atomically assigns the sequence and records queue work in its SQLite outbox    |
| Search                          | monthly GuildSearchPartitionDO            | FTS5 partitions updated through the queue                                                    |
| Presence and sessions           | GuildPresenceDO / UserSessionDO           | Hibernation WebSockets                                                                       |
| Live voice state                | VoiceRoomDO                               | Participant and live track control only; media packets are never persisted                   |
| Voice usage                     | Identity D1 via Queue                     | Join duration, track-type seconds, and transfer estimate only; no media content              |
| User media                      | R2                                        | Attachments, avatars, emoji, stickers, soundboard, voice messages, exports, desktop releases |
| Public cache                    | KV                                        | Public configuration and previews only; never authorization state                            |

Public IDs and the first-party sequence values are decimal strings. `IdGeneratorDO` is split into 1,024 named objects and uses the Discord epoch and bit layout. Identity email jobs use an encrypted D1 transactional outbox, while channel archive/search jobs use a SQLite Durable Object outbox with alarms. Queue receipts and idempotent target writes make delivery retry-safe. Authenticated first-party writes accept an encrypted 24-hour `Idempotency-Key` replay record; the same key cannot be reused with another request body.

## Voice selection

Rooms accept at most 50 participants and five concurrent screen shares. Up to ten participants subscribe to all other audio tracks. Larger rooms select at most eight remote tracks per receiver. Priority and pinned speakers win first; recent speakers are retained for 750 ms; level reports arrive every 250 ms. The browser publishes Opus audio and optional camera/display tracks through Cloudflare Realtime. `VoiceRoomDO` stores only control-plane state. On exit it emits an idempotent Queue event containing duration and track-type metadata; the 30-day operator estimate never contains RTP packets or encoded media.

## Environment isolation

`dev`, `staging`, and `prod` receive independently named D1, R2, KV, Queue, Durable Object, Realtime, Turnstile, and secret resources. `infra/resource-pools.json` is the source of truth. Run `npm run infra:plan`; provisioning needs an explicit `--apply`, and production additionally needs `--confirm-production`.
