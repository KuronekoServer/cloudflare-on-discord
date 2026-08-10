import { expect, test, type APIRequestContext } from "@playwright/test";
import { createHash } from "node:crypto";
import * as OTPAuth from "otpauth";

test("serves the PWA and public discovery document", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "CloudCord" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "ログイン" }).first(),
  ).toBeVisible();
  const discovery = await request.get("/.well-known/cloudcord");
  expect(discovery.ok()).toBeTruthy();
  expect(await discovery.json()).toMatchObject({ version: "0.1.0" });
});

test("has no media capture history route", async ({ request }) => {
  const response = await request.post("/api/v1/voice/history");
  expect(response.status()).toBe(401);
});

test("registers, verifies, creates a guild, and orders a message", async ({
  request,
}) => {
  test.setTimeout(120_000);
  const suffix = `${Date.now()}${Math.floor(Math.random() * 10_000)}`;
  const email = `e2e-${suffix}@example.test`;
  const registration = await request.post("/api/v1/auth/register", {
    data: {
      email,
      username: `e2e_${suffix}`,
      displayName: "E2E User",
      password: "correct horse battery staple",
      turnstileToken: "local-dev",
    },
  });
  expect(registration.status()).toBe(201);
  expect(
    Number(registration.headers()["x-ratelimit-remaining"]),
  ).toBeGreaterThan(0);
  const setup = (await registration.json()) as {
    developmentEmailToken: string;
    totpUri: string;
  };
  expect(
    (
      await request.post("/api/v1/auth/verify-email", {
        data: { token: setup.developmentEmailToken },
      })
    ).ok(),
  ).toBeTruthy();

  const totp = OTPAuth.URI.parse(setup.totpUri);
  if (!(totp instanceof OTPAuth.TOTP))
    throw new Error("Expected a TOTP setup URI");
  const login = await request.post("/api/v1/auth/login", {
    data: {
      email,
      password: "correct horse battery staple",
      totp: totp.generate(),
    },
  });
  expect(login.ok()).toBeTruthy();
  const session = (await login.json()) as { accessToken: string };
  const headers = { authorization: `Bearer ${session.accessToken}` };
  const deniedOrigin = await request.post("/api/v1/guilds", {
    headers: { ...headers, origin: "https://untrusted.example" },
    data: { name: "Must not be created" },
  });
  expect(deniedOrigin.status()).toBe(403);
  expect(await deniedOrigin.json()).toMatchObject({ code: "ORIGIN_DENIED" });
  expect(
    (await request.post("/api/v1/voice/history", { headers })).status(),
  ).toBe(404);
  const desktopVerifier = "desktop-pkce-verifier-".padEnd(64, "x");
  const desktopChallenge = createHash("sha256")
    .update(desktopVerifier)
    .digest("base64url");
  const desktopAuthorization = await request.post(
    "/api/v1/auth/desktop/authorize",
    {
      headers,
      data: {
        challenge: desktopChallenge,
        redirectUri: "cloudcord://auth/callback",
      },
    },
  );
  expect(desktopAuthorization.ok()).toBeTruthy();
  const desktopDeepLink = new URL(
    ((await desktopAuthorization.json()) as { deepLink: string }).deepLink,
  );
  const desktopCode = desktopDeepLink.searchParams.get("code");
  expect(desktopCode).toBeTruthy();
  const desktopExchange = await request.post("/api/v1/auth/desktop/token", {
    data: {
      code: desktopCode,
      verifier: desktopVerifier,
      redirectUri: "cloudcord://auth/callback",
    },
  });
  expect(desktopExchange.ok()).toBeTruthy();
  expect(await desktopExchange.json()).toMatchObject({
    accessToken: expect.any(String),
    refreshToken: expect.any(String),
  });
  expect(
    (
      await request.post("/api/v1/auth/desktop/token", {
        data: {
          code: desktopCode,
          verifier: desktopVerifier,
          redirectUri: "cloudcord://auth/callback",
        },
      })
    ).status(),
  ).toBe(400);

  const guildHeaders = {
    ...headers,
    "idempotency-key": `guild-${suffix}`,
  };
  const guildResponse = await request.post("/api/v1/guilds", {
    headers: guildHeaders,
    data: { name: "E2E Guild" },
  });
  expect(guildResponse.status()).toBe(201);
  const guild = (await guildResponse.json()) as {
    id: string;
    defaultChannelId: string;
  };
  const replayedGuild = await request.post("/api/v1/guilds", {
    headers: guildHeaders,
    data: { name: "E2E Guild" },
  });
  expect(replayedGuild.status()).toBe(201);
  expect(replayedGuild.headers()["idempotency-replayed"]).toBe("true");
  expect(await replayedGuild.json()).toMatchObject({ id: guild.id });
  expect(
    (
      await request.post("/api/v1/guilds", {
        headers: guildHeaders,
        data: { name: "Different Guild" },
      })
    ).status(),
  ).toBe(409);

  const forumResponse = await request.post(
    `/api/v1/guilds/${guild.id}/channels`,
    {
      headers,
      data: { name: "e2e-forum", type: "GUILD_FORUM" },
    },
  );
  expect(forumResponse.status()).toBe(201);
  const forum = (await forumResponse.json()) as { id: string };
  const threadResponse = await request.post(
    `/api/v1/channels/${forum.id}/threads`,
    {
      headers,
      data: {
        name: "First forum post",
        content: "Forum thread content",
        autoArchiveMinutes: 60,
      },
    },
  );
  expect(threadResponse.status()).toBe(201);
  const thread = (await threadResponse.json()) as {
    thread: { id: string; parentId: string; type: string };
    message: { content: string };
  };
  expect(thread.thread).toMatchObject({
    parentId: forum.id,
    type: "PUBLIC_THREAD",
  });
  expect(thread.message.content).toBe("Forum thread content");
  const threadHistory = await request.get(
    `/api/v1/channels/${thread.thread.id}/messages`,
    { headers },
  );
  expect(threadHistory.ok()).toBeTruthy();
  expect(await threadHistory.json()).toMatchObject({
    messages: [expect.objectContaining({ content: "Forum thread content" })],
  });

  const voiceResponse = await request.post(
    `/api/v1/guilds/${guild.id}/channels`,
    {
      headers,
      data: { name: "e2e-voice", type: "GUILD_VOICE" },
    },
  );
  expect(voiceResponse.status()).toBe(201);
  const voice = (await voiceResponse.json()) as { id: string };
  const stageResponse = await request.post(
    `/api/v1/guilds/${guild.id}/channels`,
    {
      headers,
      data: { name: "e2e-stage", type: "GUILD_STAGE_VOICE" },
    },
  );
  expect(stageResponse.status()).toBe(201);
  const stage = (await stageResponse.json()) as { id: string };
  expect(
    (
      await request.post(`/api/v1/voice/${voice.id}/join`, {
        headers,
        data: { muted: false, deafened: false, camera: false },
      })
    ).status(),
  ).toBe(201);
  expect(
    (await request.delete(`/api/v1/voice/${voice.id}`, { headers })).status(),
  ).toBe(204);

  const directoryUpdate = await request.patch(
    `/api/v1/guilds/${guild.id}/directory`,
    {
      headers,
      data: { enabled: true },
    },
  );
  expect(directoryUpdate.ok()).toBeTruthy();
  expect(await (await request.get("/api/v1/directory")).json()).toMatchObject({
    guilds: expect.arrayContaining([
      expect.objectContaining({ guildId: guild.id, memberCount: 1 }),
    ]),
  });
  const inviteResponse = await request.post(
    `/api/v1/guilds/${guild.id}/invites`,
    {
      headers,
      data: { channelId: guild.defaultChannelId, maxUses: 5 },
    },
  );
  expect(inviteResponse.status()).toBe(201);
  const invite = (await inviteResponse.json()) as { code: string };
  expect(
    (await request.get(`/api/v1/invites/${invite.code}/preview`)).ok(),
  ).toBeTruthy();

  const secondHeaders = await registerAndLogin(request, `${suffix}b`);
  expect(
    (
      await request.post(`/api/v1/invites/${invite.code}`, {
        headers: secondHeaders,
      })
    ).ok(),
  ).toBeTruthy();
  const members = await request.get(`/api/v1/guilds/${guild.id}/members`, {
    headers,
  });
  expect(
    ((await members.json()) as { members: unknown[] }).members,
  ).toHaveLength(2);

  const automod = await request.post(`/api/v1/guilds/${guild.id}/automod`, {
    headers,
    data: {
      name: "Blocked terms",
      keywords: ["forbidden-e2e"],
      action: "block",
    },
  });
  expect(automod.status()).toBe(201);
  expect(
    (
      await request.post(
        `/api/v1/channels/${guild.defaultChannelId}/messages`,
        {
          headers: secondHeaders,
          data: { content: "forbidden-e2e", attachmentIds: [] },
        },
      )
    ).status(),
  ).toBe(400);

  const secondMessage = await request.post(
    `/api/v1/channels/${guild.defaultChannelId}/messages`,
    {
      headers: secondHeaders,
      data: { content: "second user message", attachmentIds: [] },
    },
  );
  expect(secondMessage.status()).toBe(201);
  const secondMe = (await (
    await request.get("/api/v1/me", { headers: secondHeaders })
  ).json()) as { id: string; username: string };
  const secondUserId = secondMe.id;
  const firstUserId = (
    (await (await request.get("/api/v1/me", { headers })).json()) as {
      id: string;
    }
  ).id;
  expect(
    (
      await request.post("/api/v1/friend-requests", {
        headers,
        data: { username: secondMe.username },
      })
    ).status(),
  ).toBe(201);
  expect(
    (
      await request.post(`/api/v1/friend-requests/${firstUserId}/accept`, {
        headers: secondHeaders,
      })
    ).ok(),
  ).toBeTruthy();
  const conversationResponse = await request.post("/api/v1/conversations", {
    headers,
    data: { userIds: [secondUserId] },
  });
  expect(conversationResponse.status()).toBe(201);
  const conversation = (await conversationResponse.json()) as {
    id: string;
    channelId: string;
  };
  const conversationList = await request.get("/api/v1/conversations", {
    headers,
  });
  expect(await conversationList.json()).toMatchObject({
    conversations: expect.arrayContaining([
      expect.objectContaining({
        id: conversation.id,
        channelId: conversation.channelId,
        displayName: expect.any(String),
        members: expect.arrayContaining([
          expect.objectContaining({ id: secondUserId }),
        ]),
      }),
    ]),
  });
  expect(
    (
      await request.post(
        `/api/v1/channels/${conversation.channelId}/messages`,
        { headers, data: { content: "hello in DM", attachmentIds: [] } },
      )
    ).status(),
  ).toBe(201);
  expect(
    await (
      await request.get(`/api/v1/channels/${conversation.channelId}/messages`, {
        headers: secondHeaders,
      })
    ).json(),
  ).toMatchObject({
    messages: expect.arrayContaining([
      expect.objectContaining({ content: "hello in DM" }),
    ]),
  });
  expect(
    (
      await request.patch(
        `/api/v1/guilds/${guild.id}/members/${secondUserId}/timeout`,
        {
          headers,
          data: { until: new Date(Date.now() + 60_000).toISOString() },
        },
      )
    ).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.post(
        `/api/v1/channels/${guild.defaultChannelId}/messages`,
        {
          headers: secondHeaders,
          data: { content: "timeout should reject", attachmentIds: [] },
        },
      )
    ).status(),
  ).toBe(403);
  await request.patch(
    `/api/v1/guilds/${guild.id}/members/${secondUserId}/timeout`,
    { headers, data: { until: null } },
  );

  const reportResponse = await request.post("/api/v1/reports", {
    headers: secondHeaders,
    data: {
      guildId: guild.id,
      targetType: "channel",
      targetId: guild.defaultChannelId,
      reason: "E2E report",
    },
  });
  expect(reportResponse.status()).toBe(201);
  const report = (await reportResponse.json()) as { id: string };
  expect(
    (
      await request.patch(`/api/v1/guilds/${guild.id}/reports/${report.id}`, {
        headers,
        data: { status: "resolved", reason: "E2E reviewed" },
      })
    ).ok(),
  ).toBeTruthy();

  expect(
    (
      await request.put(`/api/v1/guilds/${guild.id}/bans/${secondUserId}`, {
        headers,
        data: { reason: "E2E moderation" },
      })
    ).status(),
  ).toBe(204);
  expect(
    (
      await request.post(`/api/v1/invites/${invite.code}`, {
        headers: secondHeaders,
      })
    ).status(),
  ).toBe(403);
  expect(
    (
      await request.delete(`/api/v1/guilds/${guild.id}/bans/${secondUserId}`, {
        headers,
      })
    ).status(),
  ).toBe(204);
  expect(
    (
      await request.post(`/api/v1/invites/${invite.code}`, {
        headers: secondHeaders,
      })
    ).ok(),
  ).toBeTruthy();
  const message = await request.post(
    `/api/v1/channels/${guild.defaultChannelId}/messages`,
    { headers, data: { content: "hello from e2e", attachmentIds: [] } },
  );
  expect(message.status()).toBe(201);
  const createdMessage = (await message.json()) as { id: string };
  expect(createdMessage).toMatchObject({
    channelId: guild.defaultChannelId,
    content: "hello from e2e",
    sequence: expect.stringMatching(/^\d+$/),
  });
  const guildList = await request.get("/api/v1/guilds", { headers });
  expect(guildList.ok()).toBeTruthy();
  expect(await guildList.json()).toMatchObject({
    guilds: [expect.objectContaining({ id: guild.id })],
  });

  const edited = await request.patch(
    `/api/v1/channels/${guild.defaultChannelId}/messages/${createdMessage.id}`,
    { headers, data: { content: "edited from e2e" } },
  );
  expect(edited.ok()).toBeTruthy();
  expect(await edited.json()).toMatchObject({
    id: createdMessage.id,
    content: "edited from e2e",
  });
  expect(
    (
      await request.put(
        `/api/v1/channels/${guild.defaultChannelId}/messages/${createdMessage.id}/reactions/%F0%9F%91%8D`,
        { headers },
      )
    ).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.put(
        `/api/v1/channels/${guild.defaultChannelId}/pins/${createdMessage.id}`,
        { headers },
      )
    ).status(),
  ).toBe(204);

  const pollResponse = await request.post(
    `/api/v1/channels/${guild.defaultChannelId}/messages`,
    {
      headers,
      data: {
        content: "choose",
        attachmentIds: [],
        poll: {
          question: "Which option?",
          answers: ["A", "B"],
          durationHours: 1,
          allowMultiselect: false,
        },
      },
    },
  );
  expect(pollResponse.status()).toBe(201);
  const pollMessage = (await pollResponse.json()) as { id: string };
  const vote = await request.put(
    `/api/v1/channels/${guild.defaultChannelId}/polls/${pollMessage.id}/answers/1`,
    { headers },
  );
  expect(vote.ok()).toBeTruthy();
  expect(await vote.json()).toMatchObject({
    answers: expect.arrayContaining([
      expect.objectContaining({ id: "1", voteCount: 1, meVoted: true }),
    ]),
  });

  const upload = await request.post("/api/v1/uploads", {
    headers,
    data: {
      filename: "hello.txt",
      contentType: "text/plain",
      size: 5,
      guildId: guild.id,
    },
  });
  expect(upload.status()).toBe(201);
  const uploadTicket = (await upload.json()) as {
    id: string;
    uploadUrl: string;
  };
  const content = await request.put(uploadTicket.uploadUrl, {
    headers: {
      ...headers,
      "content-length": "5",
      "content-type": "text/plain",
    },
    data: "hello",
  });
  expect(content.status()).toBe(204);
  const attachmentMessage = await request.post(
    `/api/v1/channels/${guild.defaultChannelId}/messages`,
    {
      headers,
      data: { content: "attachment", attachmentIds: [uploadTicket.id] },
    },
  );
  expect(attachmentMessage.status()).toBe(201);
  const attachment = (await attachmentMessage.json()) as {
    attachments: { url: string }[];
  };
  const downloaded = await request.get(attachment.attachments[0]!.url, {
    headers,
  });
  expect(await downloaded.text()).toBe("hello");

  expect(
    (
      await request.delete(
        `/api/v1/channels/${guild.defaultChannelId}/messages/${createdMessage.id}`,
        { headers },
      )
    ).status(),
  ).toBe(204);
  const history = await request.get(
    `/api/v1/channels/${guild.defaultChannelId}/messages`,
    { headers },
  );
  const historyBody = (await history.json()) as {
    messages: { id: string }[];
  };
  expect(historyBody.messages.some(({ id }) => id === createdMessage.id)).toBe(
    false,
  );

  const applicationResponse = await request.post("/api/v1/applications", {
    headers,
    data: { name: "E2E Bot", intents: "512" },
  });
  expect(applicationResponse.status()).toBe(201);
  const application = (await applicationResponse.json()) as {
    id: string;
    botUserId: string;
    token: string;
  };
  const botManagerPermissions = (
    (1n << 4n) |
    (1n << 5n) |
    (1n << 28n) |
    (1n << 29n) |
    (1n << 33n) |
    (1n << 35n) |
    (1n << 36n) |
    (1n << 51n)
  ).toString();
  const oauthPreview = await request.get("/api/v1/oauth2/authorize", {
    headers,
    params: {
      client_id: application.id,
      scope: "bot applications.commands",
      permissions: botManagerPermissions,
      guild_id: guild.id,
    },
  });
  expect(oauthPreview.ok()).toBeTruthy();
  expect(await oauthPreview.json()).toMatchObject({
    application: { id: application.id, name: "E2E Bot" },
    permissions: botManagerPermissions,
    guilds: expect.arrayContaining([
      expect.objectContaining({ id: guild.id, name: "E2E Guild" }),
    ]),
  });
  const installResponse = await request.post(
    `/api/v1/guilds/${guild.id}/bots/${application.id}`,
    {
      headers,
      data: { permissions: botManagerPermissions },
    },
  );
  expect(installResponse.status()).toBe(201);
  expect(await installResponse.json()).toEqual(
    expect.objectContaining({
      roleId: application.botUserId,
      permissions: botManagerPermissions,
    }),
  );
  const botHeaders = { authorization: `Bot ${application.token}` };
  const botAutoModResponse = await request.post(
    `/api/v10/guilds/${guild.id}/auto-moderation/rules`,
    {
      headers: botHeaders,
      data: {
        name: "Bot AutoMod",
        event_type: 1,
        trigger_type: 1,
        trigger_metadata: { keyword_filter: ["blocked-by-bot"] },
        actions: [{ type: 1 }],
        enabled: true,
      },
    },
  );
  expect(botAutoModResponse.status()).toBe(201);
  const botAutoMod = (await botAutoModResponse.json()) as { id: string };
  expect(botAutoMod).toMatchObject({
    guild_id: guild.id,
    name: "Bot AutoMod",
    trigger_metadata: {
      keyword_filter: ["blocked-by-bot"],
    },
    actions: [{ type: 1 }],
  });
  const editedAutoModResponse = await request.patch(
    `/api/v10/guilds/${guild.id}/auto-moderation/rules/${botAutoMod.id}`,
    {
      headers: botHeaders,
      data: {
        name: "Bot AutoMod edited",
        trigger_metadata: { keyword_filter: ["blocked-edited"] },
        enabled: false,
      },
    },
  );
  expect(editedAutoModResponse.ok()).toBeTruthy();
  expect(await editedAutoModResponse.json()).toMatchObject({
    id: botAutoMod.id,
    name: "Bot AutoMod edited",
    enabled: false,
    trigger_metadata: { keyword_filter: ["blocked-edited"] },
  });
  expect(
    (
      await request.get(
        `/api/v10/guilds/${guild.id}/auto-moderation/rules/${botAutoMod.id}`,
        { headers: botHeaders },
      )
    ).ok(),
  ).toBeTruthy();
  const stageInstanceResponse = await request.post("/api/v10/stage-instances", {
    headers: botHeaders,
    data: {
      channel_id: stage.id,
      topic: "E2E Stage topic",
      privacy_level: 2,
    },
  });
  expect(stageInstanceResponse.status()).toBe(201);
  expect(await stageInstanceResponse.json()).toMatchObject({
    channel_id: stage.id,
    guild_id: guild.id,
    topic: "E2E Stage topic",
  });
  const botForumThreadResponse = await request.post(
    `/api/v10/channels/${forum.id}/threads`,
    {
      headers: botHeaders,
      data: {
        name: "Bot forum thread",
        auto_archive_duration: 60,
        message: { content: "Created through Discord v10" },
      },
    },
  );
  expect(botForumThreadResponse.status()).toBe(201);
  const botForumThread = (await botForumThreadResponse.json()) as {
    id: string;
  };
  expect(botForumThread).toMatchObject({
    parent_id: forum.id,
    type: 11,
    name: "Bot forum thread",
    message: { content: "Created through Discord v10" },
  });
  const threadMembersResponse = await request.get(
    `/api/v10/channels/${botForumThread.id}/thread-members`,
    { headers: botHeaders },
  );
  expect(threadMembersResponse.ok()).toBeTruthy();
  expect(await threadMembersResponse.json()).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ user_id: application.botUserId }),
    ]),
  );
  const scheduledEventResponse = await request.post(
    `/api/v10/guilds/${guild.id}/scheduled-events`,
    {
      headers: botHeaders,
      data: {
        channel_id: voice.id,
        name: "Bot scheduled event",
        scheduled_start_time: new Date(Date.now() + 3_600_000).toISOString(),
        entity_type: 2,
        privacy_level: 2,
      },
    },
  );
  expect(scheduledEventResponse.status()).toBe(201);
  const scheduledEvent = (await scheduledEventResponse.json()) as {
    id: string;
  };
  expect(scheduledEvent).toMatchObject({
    guild_id: guild.id,
    channel_id: voice.id,
    name: "Bot scheduled event",
    status: 1,
  });
  const activeEventResponse = await request.patch(
    `/api/v10/guilds/${guild.id}/scheduled-events/${scheduledEvent.id}`,
    {
      headers: botHeaders,
      data: { name: "Bot event active", status: 2 },
    },
  );
  expect(activeEventResponse.ok()).toBeTruthy();
  expect(await activeEventResponse.json()).toMatchObject({
    id: scheduledEvent.id,
    name: "Bot event active",
    status: 2,
  });
  expect(
    (
      await request.get(
        `/api/v10/guilds/${guild.id}/scheduled-events/${scheduledEvent.id}`,
        { headers: botHeaders },
      )
    ).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.delete(
        `/api/v10/guilds/${guild.id}/scheduled-events/${scheduledEvent.id}`,
        { headers: botHeaders },
      )
    ).status(),
  ).toBe(204);
  const botRoleResponse = await request.post(
    `/api/v1/guilds/${guild.id}/roles`,
    {
      headers,
      data: { name: "Bot Manager", permissions: botManagerPermissions },
    },
  );
  expect(botRoleResponse.status()).toBe(201);
  const botRole = (await botRoleResponse.json()) as { id: string };
  expect(
    (
      await request.put(
        `/api/v1/guilds/${guild.id}/members/${application.botUserId}/roles`,
        { headers, data: { roleIds: [botRole.id] } },
      )
    ).ok(),
  ).toBeTruthy();
  expect(
    (await request.get("/api/v10/gateway/bot", { headers: botHeaders })).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.get(`/api/v10/guilds/${guild.id}`, { headers: botHeaders })
    ).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.get(`/api/v10/channels/${guild.defaultChannelId}`, {
        headers: botHeaders,
      })
    ).ok(),
  ).toBeTruthy();
  const commandResponse = await request.post(
    `/api/v10/applications/${application.id}/guilds/${guild.id}/commands`,
    {
      headers: botHeaders,
      data: { name: "hello", description: "Say hello", type: 1 },
    },
  );
  expect(commandResponse.status()).toBe(201);
  const command = (await commandResponse.json()) as { id: string };
  expect(command).toMatchObject({
    application_id: application.id,
    guild_id: guild.id,
    name: "hello",
  });
  const webhookResponse = await request.post(
    `/api/v10/channels/${guild.defaultChannelId}/webhooks`,
    { headers: botHeaders, data: { name: "E2E Webhook" } },
  );
  expect(webhookResponse.ok()).toBeTruthy();
  const webhook = (await webhookResponse.json()) as {
    id: string;
    token: string;
  };
  const webhookMessage = await request.post(
    `/api/v10/webhooks/${webhook.id}/${webhook.token}?wait=true`,
    { data: { content: "hello from webhook" } },
  );
  expect(webhookMessage.ok()).toBeTruthy();
  expect(await webhookMessage.json()).toMatchObject({
    content: "hello from webhook",
    webhook_id: webhook.id,
  });
  const botMessage = await request.post(
    `/api/v10/channels/${guild.defaultChannelId}/messages`,
    { headers: botHeaders, data: { content: "hello from bot" } },
  );
  expect(botMessage.ok()).toBeTruthy();
  const botMessageBody = (await botMessage.json()) as { id: string };
  expect(botMessageBody).toMatchObject({
    channel_id: guild.defaultChannelId,
    content: "hello from bot",
    author: { bot: true },
  });
  const botPollResponse = await request.post(
    `/api/v10/channels/${guild.defaultChannelId}/messages`,
    {
      headers: botHeaders,
      data: {
        poll: {
          question: { text: "Bot poll" },
          answers: [
            { poll_media: { text: "Yes" } },
            { poll_media: { text: "No" } },
          ],
          duration: 24,
          allow_multiselect: false,
        },
      },
    },
  );
  expect(botPollResponse.ok()).toBeTruthy();
  const botPoll = (await botPollResponse.json()) as {
    id: string;
    poll: { question: { text: string } };
  };
  expect(botPoll.poll.question.text).toBe("Bot poll");
  expect(
    (
      await request.put(
        `/api/v10/channels/${guild.defaultChannelId}/polls/${botPoll.id}/answers/1/@me`,
        { headers: botHeaders },
      )
    ).status(),
  ).toBe(204);
  const botMessageId = botMessageBody.id;
  expect(botMessageId).toBeTruthy();
  expect(
    (
      await request.patch(
        `/api/v10/channels/${guild.defaultChannelId}/messages/${botMessageId}`,
        { headers: botHeaders, data: { content: "edited by bot" } },
      )
    ).ok(),
  ).toBeTruthy();
  expect(
    (
      await request.put(
        `/api/v10/channels/${guild.defaultChannelId}/messages/${botMessageId}/reactions/%F0%9F%91%8D/@me`,
        { headers: botHeaders },
      )
    ).status(),
  ).toBe(204);
  expect(
    (
      await request.put(
        `/api/v10/channels/${guild.defaultChannelId}/pins/${botMessageId}`,
        { headers: botHeaders },
      )
    ).status(),
  ).toBe(204);
  const gatewayEvents = await new Promise<Record<string, unknown>[]>(
    (resolve, reject) => {
      const socket = new WebSocket("ws://127.0.0.1:8787/api/v10/gateway");
      const events: Record<string, unknown>[] = [];
      let eventMessageSent = false;
      let gatewayMessageReceived = false;
      let interactionReplyReceived = false;
      const timeout = setTimeout(
        () =>
          reject(new Error(`Bot Gateway timeout: ${JSON.stringify(events)}`)),
        20_000,
      );
      socket.addEventListener("message", async (event) => {
        const payload = JSON.parse(String(event.data)) as Record<
          string,
          unknown
        >;
        events.push(payload);
        if (payload.op === 10)
          socket.send(
            JSON.stringify({
              op: 2,
              d: {
                token: application.token,
                intents: 512,
                properties: { os: "e2e", browser: "e2e", device: "e2e" },
              },
            }),
          );
        if (payload.t === "READY" && !eventMessageSent) {
          eventMessageSent = true;
          const eventResponse = await request.post(
            `/api/v1/channels/${guild.defaultChannelId}/messages`,
            {
              headers: {
                ...headers,
                "idempotency-key": `gateway-message-${suffix}`,
              },
              data: { content: "gateway event" },
            },
          );
          if (!eventResponse.ok()) {
            clearTimeout(timeout);
            socket.close(1011, "E2E message failed");
            reject(
              new Error(
                `Gateway trigger message failed: ${eventResponse.status()} ${await eventResponse.text()}`,
              ),
            );
          }
          const interactionResponse = await request.post(
            "/api/v1/interactions",
            {
              headers,
              data: {
                applicationId: application.id,
                guildId: guild.id,
                channelId: guild.defaultChannelId,
                commandId: command.id,
                data: { options: [] },
              },
            },
          );
          if (interactionResponse.status() !== 202) {
            clearTimeout(timeout);
            socket.close(1011, "E2E interaction failed");
            reject(
              new Error(
                `Interaction dispatch failed: ${interactionResponse.status()} ${await interactionResponse.text()}`,
              ),
            );
          }
        }
        if (payload.t === "INTERACTION_CREATE") {
          const interaction = payload.d as {
            id: string;
            application_id: string;
            token: string;
          };
          const callback = await request.post(
            `/api/v10/interactions/${interaction.id}/${interaction.token}/callback`,
            { data: { type: 5 } },
          );
          if (callback.status() !== 204) {
            clearTimeout(timeout);
            socket.close(1011, "E2E callback failed");
            reject(
              new Error(
                `Interaction callback failed: ${callback.status()} ${await callback.text()}`,
              ),
            );
          }
          const followup = await request.post(
            `/api/v10/webhooks/${interaction.application_id}/${interaction.token}`,
            { data: { content: "interaction pong" } },
          );
          if (!followup.ok()) {
            clearTimeout(timeout);
            socket.close(1011, "E2E followup failed");
            reject(
              new Error(
                `Interaction followup failed: ${followup.status()} ${await followup.text()}`,
              ),
            );
            return;
          }
          const originalUrl = `/api/v10/webhooks/${interaction.application_id}/${interaction.token}/messages/@original`;
          const original = await request.get(originalUrl);
          if (!original.ok()) {
            clearTimeout(timeout);
            socket.close(1011, "E2E original response failed");
            reject(
              new Error(
                `Interaction original response failed: ${original.status()} ${await original.text()}`,
              ),
            );
            return;
          }
          const edited = await request.patch(originalUrl, {
            data: { content: "interaction pong edited" },
          });
          if (!edited.ok()) {
            clearTimeout(timeout);
            socket.close(1011, "E2E original edit failed");
            reject(
              new Error(
                `Interaction original edit failed: ${edited.status()} ${await edited.text()}`,
              ),
            );
          }
        }
        if (
          payload.t === "MESSAGE_CREATE" &&
          (payload.d as { content?: string } | undefined)?.content ===
            "gateway event"
        )
          gatewayMessageReceived = true;
        if (
          payload.t === "MESSAGE_CREATE" &&
          (payload.d as { content?: string } | undefined)?.content ===
            "interaction pong"
        )
          interactionReplyReceived = true;
        if (gatewayMessageReceived && interactionReplyReceived) {
          clearTimeout(timeout);
          socket.close(1000, "E2E complete");
          resolve(events);
        }
      });
      socket.addEventListener("error", () =>
        reject(new Error("Bot Gateway connection failed")),
      );
    },
  );
  expect(gatewayEvents).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ op: 10 }),
      expect.objectContaining({ op: 0, t: "READY" }),
      expect.objectContaining({ op: 0, t: "MESSAGE_CREATE" }),
      expect.objectContaining({ op: 0, t: "INTERACTION_CREATE" }),
    ]),
  );

  const exportResponse = await request.post("/api/v1/me/export", {
    headers: {
      ...headers,
      "idempotency-key": `export-${suffix}`,
    },
  });
  expect(exportResponse.status()).toBe(202);
  const exportJob = (await exportResponse.json()) as { id: string };
  let exportStatus: { phase?: string; objectKey?: string } = {};
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const statusResponse = await request.get(
      `/api/v1/me/lifecycle/${exportJob.id}`,
      { headers },
    );
    expect(statusResponse.ok()).toBeTruthy();
    exportStatus = await statusResponse.json();
    if (["complete", "errored"].includes(exportStatus.phase ?? "")) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  expect(exportStatus.phase).toBe("complete");
  const exportFile = await request.get(
    `/api/v1/me/lifecycle/${exportJob.id}/file`,
    { headers },
  );
  expect(exportFile.ok()).toBeTruthy();
  expect(await exportFile.json()).toMatchObject({
    user: { username: `e2e_${suffix}` },
  });

  const recoveryRequest = await request.post("/api/v1/auth/recovery/request", {
    data: { email, turnstileToken: "local-dev" },
  });
  expect(recoveryRequest.status()).toBe(202);
  const recovery = (await recoveryRequest.json()) as {
    developmentRecoveryToken: string;
  };
  expect(
    (
      await request.post("/api/v1/auth/recovery/complete", {
        data: {
          token: recovery.developmentRecoveryToken,
          newPassword: "new correct horse battery staple",
        },
      })
    ).ok(),
  ).toBeTruthy();
  expect((await request.get("/api/v1/me", { headers })).status()).toBe(401);
});

async function registerAndLogin(
  request: APIRequestContext,
  suffix: string,
): Promise<{ authorization: string }> {
  const email = `e2e-${suffix}@example.test`;
  const registration = await request.post("/api/v1/auth/register", {
    data: {
      email,
      username: `e2e_${suffix}`,
      displayName: "Second E2E User",
      password: "correct horse battery staple",
      turnstileToken: "local-dev",
    },
  });
  expect(registration.status()).toBe(201);
  const setup = (await registration.json()) as {
    developmentEmailToken: string;
    totpUri: string;
  };
  expect(
    (
      await request.post("/api/v1/auth/verify-email", {
        data: { token: setup.developmentEmailToken },
      })
    ).ok(),
  ).toBeTruthy();
  const totp = OTPAuth.URI.parse(setup.totpUri);
  if (!(totp instanceof OTPAuth.TOTP))
    throw new Error("Expected a TOTP setup URI");
  const login = await request.post("/api/v1/auth/login", {
    data: {
      email,
      password: "correct horse battery staple",
      totp: totp.generate(),
    },
  });
  expect(login.ok()).toBeTruthy();
  const session = (await login.json()) as { accessToken: string };
  return { authorization: `Bearer ${session.accessToken}` };
}
