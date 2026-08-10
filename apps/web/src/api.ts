export const API_BASE = import.meta.env.VITE_API_BASE ?? "/api/v1";
const DESKTOP_ACCOUNT = "primary";

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class ApiClient {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private initialized = false;

  constructor() {
    this.accessToken = sessionStorage.getItem("cloudcord.access");
    if (!this.desktop)
      this.refreshToken = localStorage.getItem("cloudcord.refresh");
  }

  get authenticated(): boolean {
    return Boolean(this.accessToken || this.refreshToken);
  }
  get token(): string | null {
    return this.accessToken;
  }
  get desktop(): boolean {
    return "__TAURI_INTERNALS__" in window;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    this.initialized = true;
    if (!this.desktop) return;
    const [{ invoke }, { getCurrent, onOpenUrl }] = await Promise.all([
      import("@tauri-apps/api/core"),
      import("@tauri-apps/plugin-deep-link"),
    ]);
    this.refreshToken = await invoke<string | null>("load_refresh_token", {
      accountId: DESKTOP_ACCOUNT,
    });
    if (this.refreshToken) await this.refresh();
    const handle = (urls: string[]) => {
      const callback = urls.find((url) =>
        url.startsWith("cloudcord://auth/callback"),
      );
      if (!callback) return;
      void this.completeDesktopLogin(callback);
    };
    await onOpenUrl(handle);
    handle((await getCurrent()) ?? []);
  }

  async beginDesktopLogin(): Promise<void> {
    if (!this.desktop)
      throw new Error("Desktop login is only available in Tauri");
    const verifier = randomBase64Url(64);
    const challenge = await pkceChallenge(verifier);
    sessionStorage.setItem("cloudcord.desktop.verifier", verifier);
    const api = new URL(API_BASE, location.href);
    const authorize = new URL("/", api.origin);
    authorize.searchParams.set("desktop_pkce", challenge);
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(authorize.toString());
  }

  async setSession(tokens: SessionTokens): Promise<void> {
    this.accessToken = tokens.accessToken;
    this.refreshToken = tokens.refreshToken;
    sessionStorage.setItem("cloudcord.access", tokens.accessToken);
    if (this.desktop) {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("save_refresh_token", {
        accountId: DESKTOP_ACCOUNT,
        token: tokens.refreshToken,
      });
      localStorage.removeItem("cloudcord.refresh");
    } else localStorage.setItem("cloudcord.refresh", tokens.refreshToken);
  }

  async clearSession(): Promise<void> {
    this.accessToken = null;
    this.refreshToken = null;
    sessionStorage.removeItem("cloudcord.access");
    localStorage.removeItem("cloudcord.refresh");
    if (this.desktop) {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("delete_refresh_token", { accountId: DESKTOP_ACCOUNT });
    }
  }

  async request<T>(
    path: string,
    init: RequestInit = {},
    retry = true,
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (
      init.body &&
      !(init.body instanceof FormData) &&
      !headers.has("content-type")
    )
      headers.set("content-type", "application/json");
    if (this.accessToken)
      headers.set("authorization", `Bearer ${this.accessToken}`);
    const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
    if (
      response.status === 401 &&
      retry &&
      this.refreshToken &&
      !path.startsWith("/auth/")
    ) {
      if (await this.refresh()) return this.request<T>(path, init, false);
    }
    if (!response.ok) {
      const error = (await response.json().catch(() => ({}))) as {
        message?: string;
      };
      throw new Error(error.message ?? `Request failed (${response.status})`);
    }
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  }

  async websocket(path: string): Promise<WebSocket> {
    if (!this.accessToken) throw new Error("Sign in first");
    const ticket = await this.request<{ ticket: string }>("/ws-ticket", {
      method: "POST",
    });
    const base = new URL(API_BASE, location.href);
    const url = new URL(`${base.pathname}${path}`, base);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("ticket", ticket.ticket);
    return new WebSocket(url);
  }

  private async refresh(): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refreshToken: this.refreshToken }),
      });
      if (!response.ok) throw new Error("Refresh rejected");
      await this.setSession((await response.json()) as SessionTokens);
      return true;
    } catch {
      await this.clearSession();
      return false;
    }
  }

  private async completeDesktopLogin(callback: string): Promise<void> {
    const code = new URL(callback).searchParams.get("code");
    const verifier = sessionStorage.getItem("cloudcord.desktop.verifier");
    if (!code || !verifier)
      throw new Error("Desktop authorization state is missing");
    const response = await fetch(`${API_BASE}/auth/desktop/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code,
        verifier,
        redirectUri: "cloudcord://auth/callback",
      }),
    });
    if (!response.ok) throw new Error("Desktop authorization was rejected");
    sessionStorage.removeItem("cloudcord.desktop.verifier");
    await this.setSession((await response.json()) as SessionTokens);
    window.dispatchEvent(new Event("cloudcord-authenticated"));
  }
}

function randomBase64Url(bytes: number): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  );
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export const api = new ApiClient();
