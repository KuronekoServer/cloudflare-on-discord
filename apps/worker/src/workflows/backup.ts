import { WorkflowEntrypoint } from "cloudflare:workers";
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import type { Env } from "../env";
import { getSecret } from "../secrets";

export interface BackupWorkflowParams {
  backupId: string;
}

interface D1DatabaseInfo {
  uuid: string;
  name: string;
}

interface ExportState {
  at_bookmark?: string;
  status?: "complete" | "error";
  error?: string;
  result?: { filename?: string; signed_url?: string };
}

export class BackupWorkflow extends WorkflowEntrypoint<
  Env,
  BackupWorkflowParams
> {
  async run(
    event: WorkflowEvent<BackupWorkflowParams>,
    step: WorkflowStep,
  ): Promise<{ objects: string[] }> {
    const accountId = this.env.CLOUDFLARE_ACCOUNT_ID;
    if (!accountId)
      throw new Error("CLOUDFLARE_ACCOUNT_ID is required for D1 backup");
    const apiToken = await getSecret(this.env, "CLOUDFLARE_BACKUP_API_TOKEN");
    const databases = await step.do("list environment D1 databases", () =>
      this.listDatabases(accountId, apiToken),
    );
    const prefix = `cloudcord-${this.env.ENVIRONMENT}-`;
    const selected = databases.filter((database) =>
      database.name.startsWith(prefix),
    );
    if (selected.length === 0)
      throw new Error(`No D1 databases matched ${prefix}`);
    const objects: string[] = [];
    for (const database of selected) {
      const key = await this.exportDatabase(
        step,
        accountId,
        apiToken,
        event.payload.backupId,
        database,
      );
      objects.push(key);
    }
    await step.do("write backup manifest", async () => {
      const key = `backups/${event.payload.backupId}/manifest.json`;
      await this.env.RELEASES.put(
        key,
        JSON.stringify(
          {
            backupId: event.payload.backupId,
            environment: this.env.ENVIRONMENT,
            createdAt: new Date().toISOString(),
            databases: selected,
            objects,
          },
          null,
          2,
        ),
        { httpMetadata: { contentType: "application/json" } },
      );
    });
    return { objects };
  }

  private async listDatabases(
    accountId: string,
    apiToken: string,
  ): Promise<D1DatabaseInfo[]> {
    const databases: D1DatabaseInfo[] = [];
    for (let page = 1; ; page += 1) {
      const response = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database?page=${page}&per_page=100`,
        { headers: { authorization: `Bearer ${apiToken}` } },
      );
      const payload = await response.json<{
        success: boolean;
        result: D1DatabaseInfo[];
        result_info?: { total_pages?: number };
      }>();
      if (!response.ok || !payload.success)
        throw new Error(`D1 database listing failed (${response.status})`);
      databases.push(...payload.result);
      if (page >= (payload.result_info?.total_pages ?? 1)) break;
    }
    return databases;
  }

  private async exportDatabase(
    step: WorkflowStep,
    accountId: string,
    apiToken: string,
    backupId: string,
    database: D1DatabaseInfo,
  ): Promise<string> {
    let state = await step.do(`start export ${database.uuid}`, () =>
      this.requestExport(accountId, apiToken, database.uuid),
    );
    for (let attempt = 0; state.status !== "complete"; attempt += 1) {
      if (state.status === "error")
        throw new Error(
          `D1 export failed for ${database.name}: ${state.error}`,
        );
      if (!state.at_bookmark || attempt >= 180)
        throw new Error(`D1 export timed out for ${database.name}`);
      await step.sleep(
        `wait for export ${database.uuid} ${attempt}`,
        "10 seconds",
      );
      state = await step.do(`poll export ${database.uuid} ${attempt}`, () =>
        this.requestExport(
          accountId,
          apiToken,
          database.uuid,
          state.at_bookmark,
        ),
      );
    }
    if (!state.result?.signed_url)
      throw new Error(`D1 export URL missing for ${database.name}`);
    const key = `backups/${backupId}/${database.name}.sql`;
    await step.do(`store export ${database.uuid}`, async () => {
      const exported = await fetch(state.result!.signed_url!);
      if (!exported.ok || !exported.body)
        throw new Error(`D1 export download failed (${exported.status})`);
      await this.env.RELEASES.put(key, exported.body, {
        httpMetadata: { contentType: "application/sql" },
        customMetadata: {
          databaseId: database.uuid,
          databaseName: database.name,
        },
      });
    });
    return key;
  }

  private async requestExport(
    accountId: string,
    apiToken: string,
    databaseId: string,
    bookmark?: string,
  ): Promise<ExportState> {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}/export`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${apiToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          output_format: "polling",
          ...(bookmark ? { current_bookmark: bookmark } : {}),
        }),
      },
    );
    const payload = await response.json<{
      success: boolean;
      result: ExportState;
    }>();
    if (!response.ok || !payload.success)
      throw new Error(`D1 export API failed (${response.status})`);
    return payload.result;
  }
}
