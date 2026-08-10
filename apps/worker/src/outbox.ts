import { decryptString, encryptString } from "./crypto";
import type { Env, QueueEvent } from "./env";

export async function prepareIdentityOutbox(
  env: Env,
  event: QueueEvent,
  encryptionKey: string,
): Promise<D1PreparedStatement> {
  const encryptedPayload = await encryptString(
    JSON.stringify(event.payload),
    encryptionKey,
  );
  return env.IDENTITY_DB.prepare(
    `INSERT INTO transactional_outbox(id,topic,partition_key,payload,available_at)
     VALUES (?1,?2,?3,?4,?5)`,
  ).bind(
    event.id,
    event.topic,
    event.partitionKey,
    encryptedPayload,
    new Date().toISOString(),
  );
}

export async function dispatchIdentityOutbox(
  env: Env,
  encryptionKey: string,
  onlyId?: string,
): Promise<number> {
  const query = onlyId
    ? env.IDENTITY_DB.prepare(
        `SELECT id,topic,partition_key,payload FROM transactional_outbox
          WHERE id=?1 AND delivered_at IS NULL AND available_at<=?2 LIMIT 1`,
      ).bind(onlyId, new Date().toISOString())
    : env.IDENTITY_DB.prepare(
        `SELECT id,topic,partition_key,payload FROM transactional_outbox
          WHERE delivered_at IS NULL AND available_at<=?1
          ORDER BY available_at LIMIT 100`,
      ).bind(new Date().toISOString());
  const rows = await query.all<{
    id: string;
    topic: QueueEvent["topic"];
    partition_key: string;
    payload: string;
  }>();
  let delivered = 0;
  for (const row of rows.results) {
    try {
      const payload = JSON.parse(
        await decryptString(row.payload, encryptionKey),
      ) as Record<string, unknown>;
      await env.EVENT_QUEUE.send({
        id: row.id,
        topic: row.topic,
        partitionKey: row.partition_key,
        payload,
      });
      await env.IDENTITY_DB.prepare(
        "UPDATE transactional_outbox SET delivered_at=?1,attempts=attempts+1 WHERE id=?2 AND delivered_at IS NULL",
      )
        .bind(new Date().toISOString(), row.id)
        .run();
      delivered += 1;
    } catch (error) {
      await env.IDENTITY_DB.prepare(
        `UPDATE transactional_outbox
            SET attempts=attempts+1,available_at=?1
          WHERE id=?2 AND delivered_at IS NULL`,
      )
        .bind(new Date(Date.now() + 60_000).toISOString(), row.id)
        .run();
      console.error(
        JSON.stringify({
          topic: "outbox-dispatch-error",
          eventId: row.id,
          error: String(error),
        }),
      );
    }
  }
  return delivered;
}
