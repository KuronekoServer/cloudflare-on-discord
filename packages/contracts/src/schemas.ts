import { z } from "zod";

export const SnowflakeSchema = z.string().regex(/^\d{17,20}$/);
export type Snowflake = z.infer<typeof SnowflakeSchema>;

export const ChannelTypeSchema = z.enum([
  "GUILD_TEXT",
  "DM",
  "GUILD_VOICE",
  "GROUP_DM",
  "GUILD_CATEGORY",
  "GUILD_ANNOUNCEMENT",
  "ANNOUNCEMENT_THREAD",
  "PUBLIC_THREAD",
  "PRIVATE_THREAD",
  "GUILD_STAGE_VOICE",
  "GUILD_FORUM",
  "GUILD_MEDIA",
]);
export type ChannelType = z.infer<typeof ChannelTypeSchema>;

export const UserSchema = z.object({
  id: SnowflakeSchema,
  username: z.string().min(2).max(32),
  displayName: z.string().min(1).max(64),
  avatarUrl: z.url().nullable(),
  bot: z.boolean().default(false),
  status: z.enum(["online", "idle", "dnd", "offline"]),
});
export type User = z.infer<typeof UserSchema>;

export const GuildSchema = z.object({
  id: SnowflakeSchema,
  ownerId: SnowflakeSchema,
  name: z.string().min(2).max(100),
  description: z.string().max(1000).nullable(),
  iconUrl: z.url().nullable(),
  memberCount: z.number().int().nonnegative(),
});
export type Guild = z.infer<typeof GuildSchema>;

export const ChannelSchema = z.object({
  id: SnowflakeSchema,
  guildId: SnowflakeSchema.nullable(),
  parentId: SnowflakeSchema.nullable(),
  name: z.string().min(1).max(100),
  type: ChannelTypeSchema,
  position: z.number().int(),
  topic: z.string().max(4096).nullable(),
  lastMessageId: SnowflakeSchema.nullable(),
});
export type Channel = z.infer<typeof ChannelSchema>;

export const AttachmentSchema = z.object({
  id: SnowflakeSchema,
  filename: z.string().min(1).max(255),
  contentType: z.string().max(128),
  size: z.number().int().nonnegative(),
  url: z.url(),
});

export const MessageSchema = z.object({
  id: SnowflakeSchema,
  channelId: SnowflakeSchema,
  author: UserSchema,
  content: z.string().max(4000),
  sequence: z.string().regex(/^\d+$/),
  createdAt: z.iso.datetime(),
  editedAt: z.iso.datetime().nullable(),
  replyToId: SnowflakeSchema.nullable(),
  attachments: z.array(AttachmentSchema),
  pinned: z.boolean(),
  reactions: z.array(
    z.object({
      emoji: z.string(),
      count: z.number().int().nonnegative(),
      me: z.boolean(),
    }),
  ),
  poll: z
    .object({
      question: z.string(),
      expiresAt: z.iso.datetime(),
      allowMultiselect: z.boolean(),
      answers: z.array(
        z.object({
          id: z.string().regex(/^\d+$/),
          text: z.string(),
          voteCount: z.number().int().nonnegative(),
          meVoted: z.boolean(),
        }),
      ),
    })
    .nullable(),
});
export type Message = z.infer<typeof MessageSchema>;

export const CreateMessageSchema = z
  .object({
    content: z.string().max(4000).default(""),
    replyToId: SnowflakeSchema.optional(),
    attachmentIds: z.array(SnowflakeSchema).max(10).default([]),
    poll: z
      .object({
        question: z.string().min(1).max(300),
        answers: z.array(z.string().min(1).max(55)).min(2).max(10),
        durationHours: z.number().int().min(1).max(768),
        allowMultiselect: z.boolean().default(false),
      })
      .optional(),
  })
  .refine(
    (value) =>
      value.content.length > 0 ||
      value.attachmentIds.length > 0 ||
      value.poll !== undefined,
    {
      message: "A message requires content or an attachment",
    },
  );

export const RegisterSchema = z.object({
  email: z.email(),
  username: z
    .string()
    .min(2)
    .max(32)
    .regex(/^[a-z0-9_.]+$/i),
  displayName: z.string().min(1).max(64),
  password: z.string().min(12).max(256),
  turnstileToken: z.string().min(1),
});

export const PasswordLoginSchema = z.object({
  email: z.email(),
  password: z.string().min(1).max(256),
  totp: z.string().regex(/^\d{6}$/),
});

export const CreateGuildSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(1000).optional(),
});

export const CreateChannelSchema = z.object({
  name: z.string().min(1).max(100),
  type: ChannelTypeSchema,
  parentId: SnowflakeSchema.optional(),
  topic: z.string().max(4096).optional(),
});

export const GatewayEnvelopeSchema = z.object({
  op: z.number().int(),
  event: z.string().optional(),
  sequence: z.string().optional(),
  data: z.unknown(),
  traceId: z.string().optional(),
});
export type GatewayEnvelope = z.infer<typeof GatewayEnvelopeSchema>;

export const VoiceJoinSchema = z.object({
  muted: z.boolean().default(false),
  deafened: z.boolean().default(false),
  camera: z.boolean().default(false),
});

export const VoiceLevelSchema = z.object({
  level: z.number().min(0).max(1),
  speaking: z.boolean(),
});

export interface ApiError {
  code: string;
  message: string;
  traceId: string;
  details?: unknown;
}
