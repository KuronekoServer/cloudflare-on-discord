import { WorkflowEntrypoint } from "cloudflare:workers";
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { decryptString } from "../crypto";
import { guildDatabase, socialDatabase } from "../data-access";
import type { Env } from "../env";
import { getSecret } from "../secrets";

export interface AccountLifecycleParams {
  jobId: string;
  userId: string;
  kind: "export" | "delete";
}

interface ActivityRow {
  channel_id: string;
  partition_key: string;
}

export class AccountLifecycleWorkflow extends WorkflowEntrypoint<
  Env,
  AccountLifecycleParams
> {
  async run(
    event: WorkflowEvent<AccountLifecycleParams>,
    step: WorkflowStep,
  ): Promise<{ objectKey?: string; deleted?: boolean }> {
    const params = event.payload;
    try {
      return params.kind === "export"
        ? await this.exportAccount(params, step)
        : await this.deleteAccount(params, step);
    } catch (cause) {
      const error = cause instanceof Error ? cause.message : String(cause);
      await step.do("record lifecycle failure", async () => {
        const timestamp = new Date().toISOString();
        const statements = [
          this.env.IDENTITY_DB.prepare(
            `UPDATE account_lifecycle_jobs
                SET phase='errored',error=?1,updated_at=?2 WHERE id=?3`,
          ).bind(error.slice(0, 2048), timestamp, params.jobId),
        ];
        if (params.kind === "delete")
          statements.push(
            this.env.IDENTITY_DB.prepare(
              `UPDATE users SET status='deletion_failed',updated_at=?1
                WHERE id=?2 AND status='deletion_pending'`,
            ).bind(timestamp, params.userId),
          );
        await this.env.IDENTITY_DB.batch(statements);
      });
      throw cause;
    }
  }

  private async exportAccount(
    params: AccountLifecycleParams,
    step: WorkflowStep,
  ): Promise<{ objectKey: string }> {
    const profileJson = await step.do<string>(
      "export identity and memberships",
      async () => {
        await this.env.IDENTITY_DB.prepare(
          "UPDATE account_lifecycle_jobs SET phase='running',updated_at=?1 WHERE id=?2",
        )
          .bind(new Date().toISOString(), params.jobId)
          .run();
        const user = await this.env.IDENTITY_DB.prepare(
          `SELECT id,email_ciphertext,username,display_name,avatar_key,status,locale,
                  created_at,updated_at FROM users WHERE id=?1`,
        )
          .bind(params.userId)
          .first<Record<string, unknown> & { email_ciphertext: string }>();
        if (!user) throw new Error("Account no longer exists");
        const encryptionKey = await getSecret(this.env, "DATA_ENCRYPTION_KEY");
        const email = await decryptString(user.email_ciphertext, encryptionKey);
        const social = await socialDatabase(this.env, params.userId);
        const [relationships, conversations, guilds, passkeys, media] =
          await Promise.all([
            social.db
              .prepare("SELECT * FROM relationships WHERE user_id=?1")
              .bind(params.userId)
              .all(),
            social.db
              .prepare(
                "SELECT * FROM conversation_membership_index WHERE user_id=?1",
              )
              .bind(params.userId)
              .all(),
            social.db
              .prepare("SELECT * FROM guild_membership_index WHERE user_id=?1")
              .bind(params.userId)
              .all(),
            this.env.IDENTITY_DB.prepare(
              "SELECT id,credential_id,transports,created_at,last_used_at FROM passkeys WHERE user_id=?1",
            )
              .bind(params.userId)
              .all(),
            this.env.IDENTITY_DB.prepare(
              `SELECT id,guild_id,object_key,filename,content_type,size_bytes,state,
                      created_at FROM media_objects WHERE owner_id=?1`,
            )
              .bind(params.userId)
              .all(),
          ]);
        const { email_ciphertext: _ciphertext, ...safeUser } = user;
        return JSON.stringify({
          exportedAt: new Date().toISOString(),
          user: { ...safeUser, email },
          relationships: relationships.results,
          conversations: conversations.results,
          guilds: guilds.results,
          passkeys: passkeys.results,
          media: media.results,
        });
      },
    );

    const activities = await this.activities(params.userId);
    const messageObjects: Array<{
      channelId: string;
      objectKey: string;
      count: number;
    }> = [];
    for (const activity of activities) {
      const exported = await step.do(
        `export channel ${activity.channel_id}`,
        async () => {
          const messages: unknown[] = [];
          let after = 0;
          while (true) {
            const url = new URL("https://do/account/messages");
            url.searchParams.set("user", params.userId);
            url.searchParams.set("after", String(after));
            const response = await this.channel(activity.channel_id).fetch(url);
            if (!response.ok)
              throw new Error("Unable to export channel messages");
            const page = await response.json<{
              messages: Array<Record<string, unknown> & { sequence: string }>;
            }>();
            messages.push(...page.messages);
            if (page.messages.length < 100) break;
            after = Number(page.messages.at(-1)!.sequence);
          }
          const objectKey = `exports/${params.userId}/${params.jobId}/messages/${activity.channel_id}.json`;
          await this.env.MEDIA.put(
            objectKey,
            JSON.stringify({ channelId: activity.channel_id, messages }),
            {
              httpMetadata: { contentType: "application/json; charset=utf-8" },
              customMetadata: { purpose: "account-export" },
            },
          );
          return { objectKey, count: messages.length };
        },
      );
      messageObjects.push({
        channelId: activity.channel_id,
        objectKey: exported.objectKey,
        count: exported.count,
      });
    }
    const objectKey = `exports/${params.userId}/${params.jobId}/manifest.json`;
    await step.do("write export manifest", async () => {
      await this.env.MEDIA.put(
        objectKey,
        JSON.stringify({
          ...(JSON.parse(profileJson) as Record<string, unknown>),
          messageObjects,
        }),
        {
          httpMetadata: { contentType: "application/json; charset=utf-8" },
          customMetadata: { purpose: "account-export" },
        },
      );
      await this.env.IDENTITY_DB.prepare(
        `UPDATE account_lifecycle_jobs
            SET phase='complete',object_key=?1,error=NULL,updated_at=?2 WHERE id=?3`,
      )
        .bind(objectKey, new Date().toISOString(), params.jobId)
        .run();
    });
    return { objectKey };
  }

  private async deleteAccount(
    params: AccountLifecycleParams,
    step: WorkflowStep,
  ): Promise<{ deleted: true }> {
    await step.do("lock account", async () => {
      const timestamp = new Date().toISOString();
      const updated = await this.env.IDENTITY_DB.prepare(
        "UPDATE users SET status='deletion_pending',updated_at=?1 WHERE id=?2 AND status='active'",
      )
        .bind(timestamp, params.userId)
        .run();
      if (updated.meta.changes !== 1)
        throw new Error("Account is not active or no longer exists");
      await this.env.IDENTITY_DB.prepare(
        "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
      )
        .bind(timestamp, params.userId)
        .run();
      await this.env.IDENTITY_DB.prepare(
        "UPDATE account_lifecycle_jobs SET phase='running',updated_at=?1 WHERE id=?2",
      )
        .bind(timestamp, params.jobId)
        .run();
    });

    for (const activity of await this.activities(params.userId))
      await step.do(`erase channel ${activity.channel_id}`, async () => {
        while (true) {
          const response = await this.channel(activity.channel_id).fetch(
            "https://do/account/messages",
            {
              method: "DELETE",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                userId: params.userId,
                partitionKey: activity.partition_key,
              }),
            },
          );
          if (!response.ok) throw new Error("Unable to erase channel messages");
          const result = await response.json<{ remaining: number }>();
          if (result.remaining === 0) break;
        }
      });

    await step.do("remove social and guild memberships", async () => {
      const social = await socialDatabase(this.env, params.userId);
      const [relationships, conversations, guilds] = await Promise.all([
        social.db
          .prepare("SELECT target_user_id FROM relationships WHERE user_id=?1")
          .bind(params.userId)
          .all<{ target_user_id: string }>(),
        social.db
          .prepare(
            "SELECT conversation_id FROM conversation_membership_index WHERE user_id=?1",
          )
          .bind(params.userId)
          .all<{ conversation_id: string }>(),
        social.db
          .prepare(
            "SELECT guild_id FROM guild_membership_index WHERE user_id=?1",
          )
          .bind(params.userId)
          .all<{ guild_id: string }>(),
      ]);
      for (const relationship of relationships.results) {
        const other = await socialDatabase(
          this.env,
          relationship.target_user_id,
        );
        await other.db
          .prepare(
            "DELETE FROM relationships WHERE user_id=?1 AND target_user_id=?2",
          )
          .bind(relationship.target_user_id, params.userId)
          .run();
      }
      for (const membership of conversations.results) {
        const conversation = await socialDatabase(
          this.env,
          membership.conversation_id,
        );
        await conversation.db
          .prepare(
            "DELETE FROM conversation_members WHERE conversation_id=?1 AND user_id=?2",
          )
          .bind(membership.conversation_id, params.userId)
          .run();
      }
      for (const membership of guilds.results) {
        const guild = await guildDatabase(this.env, membership.guild_id);
        await guild.db
          .prepare("DELETE FROM members WHERE guild_id=?1 AND user_id=?2")
          .bind(membership.guild_id, params.userId)
          .run();
        const count = await guild.db
          .prepare("SELECT count(*) AS count FROM members WHERE guild_id=?1")
          .bind(membership.guild_id)
          .first<{ count: number }>();
        await this.env.IDENTITY_DB.prepare(
          "UPDATE guild_directory SET member_count=?1,updated_at=?2 WHERE guild_id=?3",
        )
          .bind(
            count?.count ?? 0,
            new Date().toISOString(),
            membership.guild_id,
          )
          .run();
      }
      await social.db.batch([
        social.db
          .prepare(
            "DELETE FROM relationships WHERE user_id=?1 OR target_user_id=?1",
          )
          .bind(params.userId),
        social.db
          .prepare("DELETE FROM conversation_membership_index WHERE user_id=?1")
          .bind(params.userId),
        social.db
          .prepare("DELETE FROM guild_membership_index WHERE user_id=?1")
          .bind(params.userId),
      ]);
    });

    await step.do("delete media and identity", async () => {
      const media = await this.env.IDENTITY_DB.prepare(
        "SELECT object_key FROM media_objects WHERE owner_id=?1",
      )
        .bind(params.userId)
        .all<{ object_key: string }>();
      for (const object of media.results)
        await this.env.MEDIA.delete(object.object_key);
      const applications = await this.env.IDENTITY_DB.prepare(
        "SELECT id FROM applications WHERE owner_id=?1",
      )
        .bind(params.userId)
        .all<{ id: string }>();
      const botUsers = await this.env.IDENTITY_DB.prepare(
        `SELECT b.user_id FROM bots b JOIN applications a ON a.id=b.application_id
          WHERE a.owner_id=?1`,
      )
        .bind(params.userId)
        .all<{ user_id: string }>();
      for (const application of applications.results)
        await this.env.IDENTITY_DB.prepare(
          "DELETE FROM applications WHERE id=?1",
        )
          .bind(application.id)
          .run();
      for (const bot of botUsers.results)
        await this.env.IDENTITY_DB.prepare("DELETE FROM users WHERE id=?1")
          .bind(bot.user_id)
          .run();
      await this.env.IDENTITY_DB.batch([
        this.env.IDENTITY_DB.prepare(
          "DELETE FROM media_objects WHERE owner_id=?1",
        ).bind(params.userId),
        this.env.IDENTITY_DB.prepare(
          "DELETE FROM user_channel_activity WHERE user_id=?1",
        ).bind(params.userId),
        this.env.IDENTITY_DB.prepare("DELETE FROM users WHERE id=?1").bind(
          params.userId,
        ),
        this.env.IDENTITY_DB.prepare(
          `UPDATE account_lifecycle_jobs
              SET phase='complete',error=NULL,updated_at=?1 WHERE id=?2`,
        ).bind(new Date().toISOString(), params.jobId),
      ]);
    });
    return { deleted: true };
  }

  private async activities(userId: string): Promise<ActivityRow[]> {
    const result = await this.env.IDENTITY_DB.prepare(
      `SELECT channel_id,partition_key FROM user_channel_activity
        WHERE user_id=?1 ORDER BY channel_id`,
    )
      .bind(userId)
      .all<ActivityRow>();
    return result.results;
  }

  private channel(channelId: string): DurableObjectStub {
    return this.env.CHANNEL_HUBS.get(
      this.env.CHANNEL_HUBS.idFromName(channelId),
    );
  }
}
