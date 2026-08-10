import type { Channel, Message } from "@cloudcord/contracts";
import {
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api, type SessionTokens } from "./api";
import { getCached, setCached } from "./offline-cache";
import { useAppStore, type GuildSummary } from "./store";

type Locale = "ja" | "en";

const labels = {
  ja: {
    login: "ログイン",
    passkeyLogin: "Passkeyでログイン",
    addPasskey: "Passkeyを追加",
    register: "アカウント作成",
    verify: "メール確認",
    welcome: "おかえりなさい",
    email: "メールアドレス",
    username: "ユーザー名",
    displayName: "表示名",
    password: "パスワード",
    totp: "TOTPコード",
    submit: "送信",
    processing: "処理中…",
    community: "コミュニティ",
    textChannels: "テキストチャンネル",
    voiceChannels: "ボイス・ステージ",
    chooseChannel: "チャンネルを選択",
    channelStart: "このチャンネルの始まりです。",
    messagePlaceholder: "メッセージを送信",
    createGuild: "サーバーを追加",
    guildName: "サーバー名",
    settings: "管理設定",
    logout: "ログアウト",
    edit: "編集",
    remove: "削除",
    pin: "ピン",
    poll: "投票",
    attach: "ファイルを添付",
    save: "保存",
    cancel: "キャンセル",
    vote: "票",
    edited: "編集済み",
    connect: "接続",
    connected: "接続中",
    microphone: "マイク",
    muted: "ミュート中",
    camera: "カメラ",
    screen: "画面共有",
    disconnect: "退出",
  },
  en: {
    login: "Sign in",
    passkeyLogin: "Sign in with a passkey",
    addPasskey: "Add passkey",
    register: "Create account",
    verify: "Verify email",
    welcome: "Welcome back",
    email: "Email address",
    username: "Username",
    displayName: "Display name",
    password: "Password",
    totp: "TOTP code",
    submit: "Continue",
    processing: "Working…",
    community: "Community",
    textChannels: "Text channels",
    voiceChannels: "Voice & stage",
    chooseChannel: "Choose a channel",
    channelStart: "This is the beginning of this channel.",
    messagePlaceholder: "Send a message",
    createGuild: "Add server",
    guildName: "Server name",
    settings: "Administration",
    logout: "Sign out",
    edit: "Edit",
    remove: "Delete",
    pin: "Pin",
    poll: "Poll",
    attach: "Attach file",
    save: "Save",
    cancel: "Cancel",
    vote: "votes",
    edited: "edited",
    connect: "Connect",
    connected: "Connected",
    microphone: "Microphone",
    muted: "Muted",
    camera: "Camera",
    screen: "Share screen",
    disconnect: "Leave",
  },
} as const;

interface Me {
  id: string;
  username: string;
  display_name: string;
  status: string;
  administrator: boolean;
}

interface ConversationSummary {
  id: string;
  kind: "dm" | "group_dm";
  name: string | null;
  displayName: string;
  channelId: string;
  members: Array<{ id: string; username: string; global_name: string | null }>;
}

interface RelationshipSummary {
  userId: string;
  kind:
    | "friend"
    | "friend_pending_incoming"
    | "friend_pending_outgoing"
    | "blocked";
  user: {
    username: string;
    displayName: string;
    avatarKey: string | null;
  };
}

export function App() {
  const [authenticated, setAuthenticated] = useState(api.authenticated);
  const [ready, setReady] = useState(false);
  const [locale, setLocale] = useState<Locale>(() =>
    localStorage.getItem("cloudcord.locale") === "en" ? "en" : "ja",
  );
  const changeLocale = (next: Locale) => {
    localStorage.setItem("cloudcord.locale", next);
    setLocale(next);
  };
  useEffect(() => {
    const signedIn = () => setAuthenticated(true);
    window.addEventListener("cloudcord-authenticated", signedIn);
    void api.initialize().finally(() => {
      setAuthenticated(api.authenticated);
      setReady(true);
    });
    return () =>
      window.removeEventListener("cloudcord-authenticated", signedIn);
  }, []);
  if (!ready) return <main className="auth-shell" aria-busy="true" />;
  const desktopChallenge = new URLSearchParams(location.search).get(
    "desktop_pkce",
  );
  if (authenticated && desktopChallenge && !api.desktop)
    return (
      <DesktopAuthorize
        locale={locale}
        challenge={desktopChallenge}
        onLocale={changeLocale}
      />
    );
  if (authenticated && location.pathname === "/oauth2/authorize")
    return <OAuthBotAuthorize locale={locale} onLocale={changeLocale} />;
  if (!authenticated)
    return (
      <AuthScreen
        locale={locale}
        onLocale={changeLocale}
        onAuthenticated={() => setAuthenticated(true)}
      />
    );
  return (
    <Workspace
      locale={locale}
      onLocale={changeLocale}
      onSignedOut={() => {
        void api.clearSession();
        setAuthenticated(false);
      }}
    />
  );
}

function OAuthBotAuthorize({
  locale,
  onLocale,
}: {
  locale: Locale;
  onLocale: (locale: Locale) => void;
}) {
  interface Authorization {
    application: { id: string; name: string; description: string };
    scopes: string[];
    permissions: string;
    requestedGuildId: string | null;
    guilds: Array<{ id: string; name: string }>;
  }
  const [authorization, setAuthorization] = useState<Authorization | null>(
    null,
  );
  const [guildId, setGuildId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [installed, setInstalled] = useState(false);
  useEffect(() => {
    void api
      .request<Authorization>(`/oauth2/authorize${location.search}`)
      .then((result) => {
        setAuthorization(result);
        setGuildId(
          result.guilds.some((guild) => guild.id === result.requestedGuildId)
            ? (result.requestedGuildId ?? "")
            : (result.guilds[0]?.id ?? ""),
        );
      })
      .catch((reason) => setError(String(reason)));
  }, []);
  const approve = async () => {
    if (!authorization || !guildId) return;
    setBusy(true);
    try {
      await api.request(
        `/guilds/${guildId}/bots/${authorization.application.id}`,
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({ permissions: authorization.permissions }),
        },
      );
      setInstalled(true);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="oauth-shell">
      <section className="oauth-card">
        <header>
          <div className="brand-mark">C</div>
          <LocaleSwitch locale={locale} onLocale={onLocale} />
        </header>
        {!authorization ? (
          <p>{error || labels[locale].processing}</p>
        ) : installed ? (
          <div className="oauth-result">
            <span>✓</span>
            <h1>{locale === "ja" ? "Botを導入しました" : "Bot installed"}</h1>
            <p>{authorization.application.name}</p>
            <button onClick={() => location.assign("/")}>
              {locale === "ja" ? "CloudCordへ戻る" : "Return to CloudCord"}
            </button>
          </div>
        ) : (
          <>
            <p className="eyebrow">OAuth2 Bot Install</p>
            <h1>{authorization.application.name}</h1>
            <p>{authorization.application.description}</p>
            <div className="oauth-request">
              <strong>
                {locale === "ja" ? "要求内容" : "Requested access"}
              </strong>
              <span>{authorization.scopes.join(", ")}</span>
              <code>permissions {authorization.permissions}</code>
            </div>
            <label>
              {locale === "ja" ? "追加先のサーバー" : "Add to server"}
              <select
                value={guildId}
                onChange={(event) => setGuildId(event.target.value)}
              >
                {authorization.guilds.map((guild) => (
                  <option key={guild.id} value={guild.id}>
                    {guild.name}
                  </option>
                ))}
              </select>
            </label>
            {error && <p className="error">{error}</p>}
            {authorization.guilds.length === 0 && (
              <p className="error">
                {locale === "ja"
                  ? "導入できる所有サーバーがありません。"
                  : "You do not own a server where this Bot can be installed."}
              </p>
            )}
            <div className="oauth-actions">
              <button
                className="secondary"
                onClick={() => location.assign("/")}
              >
                {locale === "ja" ? "キャンセル" : "Cancel"}
              </button>
              <button
                className="primary"
                disabled={busy || !guildId}
                onClick={() => void approve()}
              >
                {busy
                  ? labels[locale].processing
                  : locale === "ja"
                    ? "認証して導入"
                    : "Authorize"}
              </button>
            </div>
          </>
        )}
      </section>
    </main>
  );
}

function DesktopAuthorize({
  locale,
  challenge,
  onLocale,
}: {
  locale: Locale;
  challenge: string;
  onLocale: (locale: Locale) => void;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function authorize() {
    setBusy(true);
    setError("");
    try {
      const result = await api.request<{ deepLink: string }>(
        "/auth/desktop/authorize",
        {
          method: "POST",
          body: JSON.stringify({
            challenge,
            redirectUri: "cloudcord://auth/callback",
          }),
        },
      );
      location.href = result.deepLink;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setBusy(false);
    }
  }
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <LocaleSwitch locale={locale} onLocale={onLocale} />
        <p className="eyebrow">CloudCord Desktop</p>
        <h1>
          {locale === "ja" ? "デスクトップ版を認証" : "Authorize desktop"}
        </h1>
        <p>
          {locale === "ja"
            ? "このアカウントでデスクトップ版へ安全に戻ります。認証コードは一回限り、5分で失効します。"
            : "Return to the desktop app with this account. The one-time authorization code expires in five minutes."}
        </p>
        {error && <p className="error-banner">{error}</p>}
        <button
          className="primary-action"
          disabled={busy}
          onClick={() => void authorize()}
        >
          {busy
            ? locale === "ja"
              ? "認証中…"
              : "Authorizing…"
            : locale === "ja"
              ? "CloudCord Desktopを開く"
              : "Open CloudCord Desktop"}
        </button>
      </section>
    </main>
  );
}

function LocaleSwitch({
  locale,
  onLocale,
}: {
  locale: Locale;
  onLocale: (locale: Locale) => void;
}) {
  return (
    <button
      className="locale-switch"
      onClick={() => onLocale(locale === "ja" ? "en" : "ja")}
      aria-label="Change language"
    >
      {locale === "ja" ? "EN" : "日本語"}
    </button>
  );
}

function AuthScreen({
  locale,
  onLocale,
  onAuthenticated,
}: {
  locale: Locale;
  onLocale: (locale: Locale) => void;
  onAuthenticated: () => void;
}) {
  const t = labels[locale];
  const [mode, setMode] = useState<"login" | "register" | "verify">("login");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [verification, setVerification] = useState<{
    token?: string;
    totpUri?: string;
  }>({});

  if (api.desktop)
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <LocaleSwitch locale={locale} onLocale={onLocale} />
          <p className="eyebrow">CloudCord Desktop</p>
          <h1>
            {locale === "ja" ? "ブラウザでログイン" : "Sign in in your browser"}
          </h1>
          <p>
            {locale === "ja"
              ? "パスワードやPasskeyはシステムブラウザで入力します。デスクトップ版には短命な認証結果だけが戻ります。"
              : "Passwords and passkeys stay in your system browser. Only a short-lived authorization result returns to the desktop app."}
          </p>
          {error && <p className="error-banner">{error}</p>}
          <button
            className="primary-action"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              setError("");
              void api.beginDesktopLogin().catch((reason: unknown) => {
                setError(
                  reason instanceof Error ? reason.message : String(reason),
                );
                setBusy(false);
              });
            }}
          >
            {busy
              ? locale === "ja"
                ? "ブラウザを開いています…"
                : "Opening browser…"
              : locale === "ja"
                ? "ブラウザで続ける"
                : "Continue in browser"}
          </button>
        </section>
      </main>
    );

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    const values = Object.fromEntries(new FormData(event.currentTarget));
    try {
      if (mode === "login") {
        const tokens = await api.request<SessionTokens>("/auth/login", {
          method: "POST",
          body: JSON.stringify({
            email: values.email,
            password: values.password,
            totp: values.totp,
          }),
        });
        await api.setSession(tokens);
        onAuthenticated();
      } else if (mode === "register") {
        const result = await api.request<{
          developmentEmailToken?: string;
          totpUri: string;
        }>("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: values.email,
            username: values.username,
            displayName: values.displayName,
            password: values.password,
            turnstileToken: values.turnstileToken || "local-dev",
          }),
        });
        setVerification({
          ...(result.developmentEmailToken
            ? { token: result.developmentEmailToken }
            : {}),
          totpUri: result.totpUri,
        });
        setMode("verify");
      } else {
        await api.request("/auth/verify-email", {
          method: "POST",
          body: JSON.stringify({ token: values.token }),
        });
        setMode("login");
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function loginWithPasskey() {
    setError("");
    setBusy(true);
    try {
      const options = await api.request<PublicKeyCredentialRequestOptionsJSON>(
        "/auth/passkey/options",
        { method: "POST", body: "{}" },
      );
      const assertion = await startAuthentication({ optionsJSON: options });
      const tokens = await api.request<SessionTokens>("/auth/passkey/verify", {
        method: "POST",
        body: JSON.stringify(assertion),
      });
      await api.setSession(tokens);
      onAuthenticated();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <LocaleSwitch locale={locale} onLocale={onLocale} />
      <section className="auth-brand">
        <div className="brand-mark">C</div>
        <p className="eyebrow">YOUR COMMUNITY · YOUR INSTANCE</p>
        <h1>CloudCord</h1>
        <p>
          {locale === "ja"
            ? "Cloudflareだけで完結する、軽快なコミュニティ空間。"
            : "A fast community space running entirely on Cloudflare."}
        </p>
        <div className="security-note">
          Passkey · 多要素認証 · Cloudflare Realtime
        </div>
      </section>
      <section className="auth-card">
        <div className="tabs">
          <button
            className={mode === "login" ? "active" : ""}
            onClick={() => setMode("login")}
          >
            {t.login}
          </button>
          <button
            className={mode === "register" ? "active" : ""}
            onClick={() => setMode("register")}
          >
            {t.register}
          </button>
        </div>
        <form onSubmit={submit}>
          <h2>
            {mode === "verify"
              ? t.verify
              : mode === "register"
                ? t.register
                : t.welcome}
          </h2>
          {mode === "verify" ? (
            <>
              <p className="muted">
                {locale === "ja"
                  ? "メールに届いた15分間有効なコードを入力してください。"
                  : "Enter the one-time code sent by email. It expires in 15 minutes."}
              </p>
              {verification.totpUri && (
                <details>
                  <summary>TOTP setup URI</summary>
                  <code>{verification.totpUri}</code>
                </details>
              )}
              <label>
                {locale === "ja" ? "確認コード" : "Verification code"}
                <input
                  name="token"
                  required
                  defaultValue={verification.token}
                  autoComplete="one-time-code"
                />
              </label>
            </>
          ) : (
            <>
              <label>
                {t.email}
                <input
                  name="email"
                  type="email"
                  required
                  autoComplete="email"
                />
              </label>
              {mode === "register" && (
                <>
                  <label>
                    {t.username}
                    <input
                      name="username"
                      required
                      minLength={2}
                      pattern="[A-Za-z0-9_.]+"
                      autoComplete="username"
                    />
                  </label>
                  <label>
                    {t.displayName}
                    <input name="displayName" required maxLength={64} />
                  </label>
                </>
              )}
              <label>
                {t.password}
                <input
                  name="password"
                  type="password"
                  required
                  minLength={mode === "register" ? 12 : 1}
                  autoComplete={
                    mode === "register" ? "new-password" : "current-password"
                  }
                />
              </label>
              {mode === "login" && (
                <label>
                  {t.totp}
                  <input
                    name="totp"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    required
                    autoComplete="one-time-code"
                  />
                </label>
              )}
              {mode === "register" && (
                <input
                  name="turnstileToken"
                  type="hidden"
                  value="local-dev"
                  readOnly
                />
              )}
            </>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <button className="primary" disabled={busy}>
            {busy ? t.processing : mode === "verify" ? t.verify : t.submit}
          </button>
          {mode === "login" && (
            <button
              className="secondary"
              type="button"
              disabled={busy}
              onClick={() => void loginWithPasskey()}
            >
              {t.passkeyLogin}
            </button>
          )}
        </form>
      </section>
    </main>
  );
}

function Workspace({
  locale,
  onLocale,
  onSignedOut,
}: {
  locale: Locale;
  onLocale: (locale: Locale) => void;
  onSignedOut: () => void;
}) {
  const t = labels[locale];
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState("");
  const [mobilePane, setMobilePane] = useState<"guilds" | "channels" | "chat">(
    "chat",
  );
  const [adminOpen, setAdminOpen] = useState(false);
  const [socialOpen, setSocialOpen] = useState(false);
  const [channelCreateOpen, setChannelCreateOpen] = useState(false);
  const [guildSettingsOpen, setGuildSettingsOpen] = useState(false);
  const [developerOpen, setDeveloperOpen] = useState(false);
  const [homeOpen, setHomeOpen] = useState(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [relationships, setRelationships] = useState<RelationshipSummary[]>([]);
  const {
    guilds,
    channels,
    messages,
    activeGuildId,
    activeChannelId,
    setGuilds,
    setChannels,
    setMessages,
    upsertMessage,
    removeMessage,
    selectGuild,
    selectChannel,
  } = useAppStore();
  const applyMessage = useCallback(
    (message: Message) => {
      upsertMessage(message);
      if (activeChannelId)
        void setCached(
          `messages:${activeChannelId}`,
          useAppStore.getState().messages,
        );
    },
    [activeChannelId, upsertMessage],
  );
  const discardMessage = useCallback(
    (id: string) => {
      removeMessage(id);
      if (activeChannelId)
        void setCached(
          `messages:${activeChannelId}`,
          useAppStore.getState().messages,
        );
    },
    [activeChannelId, removeMessage],
  );

  const refreshSocial = useCallback(async () => {
    const [conversationResult, relationshipResult] = await Promise.all([
      api.request<{ conversations: ConversationSummary[] }>("/conversations"),
      api.request<{ relationships: RelationshipSummary[] }>("/relationships"),
    ]);
    setConversations(conversationResult.conversations);
    setRelationships(relationshipResult.relationships);
  }, []);

  useEffect(() => {
    void api
      .request<Me>("/me")
      .then(setMe)
      .catch((reason) => setError(String(reason)));
    void api
      .request<{ guilds: GuildSummary[] }>("/guilds")
      .then((result) => {
        setGuilds(result.guilds);
        void setCached("guilds", result.guilds);
      })
      .catch(async (reason) => {
        const cached = await getCached<GuildSummary[]>("guilds").catch(
          () => null,
        );
        if (cached) setGuilds(cached);
        else setError(String(reason));
      });
    void refreshSocial().catch((reason) => setError(String(reason)));
  }, [refreshSocial, setGuilds]);

  useEffect(() => {
    if (!activeGuildId) return;
    void api
      .request<{ channels: Channel[] }>(`/guilds/${activeGuildId}/channels`)
      .then((result) => {
        setChannels(result.channels);
        void setCached(`channels:${activeGuildId}`, result.channels);
      })
      .catch(async (reason) => {
        const cached = await getCached<Channel[]>(
          `channels:${activeGuildId}`,
        ).catch(() => null);
        if (cached) setChannels(cached);
        else setError(String(reason));
      });
  }, [activeGuildId, setChannels]);

  useEffect(() => {
    if (!activeChannelId) return;
    let socket: WebSocket | undefined;
    void api
      .request<{ messages: Message[] }>(`/channels/${activeChannelId}/messages`)
      .then((result) => {
        setMessages(result.messages);
        void setCached(`messages:${activeChannelId}`, result.messages);
      })
      .catch(async (reason) => {
        const cached = await getCached<Message[]>(
          `messages:${activeChannelId}`,
        ).catch(() => null);
        if (cached) setMessages(cached);
        else setError(String(reason));
      });
    void api
      .websocket(`/channels/${activeChannelId}/stream`)
      .then((createdSocket) => {
        socket = createdSocket;
        socket.addEventListener("message", (event) => {
          const envelope = JSON.parse(String(event.data)) as {
            event?: string;
            data?: Message & { id: string };
          };
          if (
            ["MESSAGE_CREATE", "MESSAGE_UPDATE"].includes(
              envelope.event ?? "",
            ) &&
            envelope.data
          )
            applyMessage(envelope.data);
          if (envelope.event === "MESSAGE_DELETE" && envelope.data?.id)
            discardMessage(envelope.data.id);
        });
      })
      .catch((reason) => setError(String(reason)));
    return () => socket?.close(1000, "Channel changed");
  }, [activeChannelId, applyMessage, discardMessage, setMessages]);

  const createGuild = async () => {
    const name = prompt(t.guildName);
    if (!name) return;
    try {
      const guild = await api.request<GuildSummary>("/guilds", {
        method: "POST",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ name }),
      });
      setGuilds([...guilds, guild]);
      selectGuild(guild.id);
      setMobilePane("channels");
    } catch (reason) {
      setError(String(reason));
    }
  };

  const sendFriendRequest = async () => {
    const username = prompt(
      locale === "ja" ? "フレンドのユーザー名" : "Friend username",
    );
    if (!username) return;
    try {
      await api.request("/friend-requests", {
        method: "POST",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ username }),
      });
      await refreshSocial();
      setSocialOpen(true);
    } catch (reason) {
      setError(String(reason));
    }
  };

  const openDm = async (userId: string) => {
    try {
      const existing = conversations.find(
        (conversation) =>
          conversation.kind === "dm" &&
          conversation.members.some((member) => member.id === userId),
      );
      const conversation =
        existing ??
        (await api.request<ConversationSummary>("/conversations", {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({ userIds: [userId] }),
        }));
      await refreshSocial();
      setHomeOpen(true);
      selectChannel(conversation.channelId);
      setSocialOpen(false);
      setMobilePane("chat");
    } catch (reason) {
      setError(String(reason));
    }
  };

  const addPasskey = async () => {
    try {
      const options = await api.request<PublicKeyCredentialCreationOptionsJSON>(
        "/passkeys/options",
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: "{}",
        },
      );
      const registration = await startRegistration({ optionsJSON: options });
      await api.request("/passkeys/verify", {
        method: "POST",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify(registration),
      });
      alert(locale === "ja" ? "Passkeyを追加しました。" : "Passkey added.");
    } catch (reason) {
      setError(String(reason));
    }
  };

  const dmChannels: Channel[] = conversations.map((conversation, position) => ({
    id: conversation.channelId,
    guildId: null,
    parentId: null,
    name: conversation.displayName || "Direct Message",
    type: conversation.kind === "dm" ? "DM" : "GROUP_DM",
    position,
    topic: null,
    lastMessageId: null,
  }));
  const visibleChannels = homeOpen ? dmChannels : channels;
  const activeGuild = homeOpen
    ? null
    : guilds.find((guild) => guild.id === activeGuildId);
  const activeChannel = visibleChannels.find(
    (channel) => channel.id === activeChannelId,
  );
  return (
    <main className={`workspace pane-${mobilePane}`}>
      <nav className="guild-rail" aria-label={t.community}>
        <button
          className={homeOpen ? "home-glyph active" : "home-glyph"}
          aria-label="CloudCord home"
          onClick={() => {
            setHomeOpen(true);
            if (dmChannels[0]) selectChannel(dmChannels[0].id);
            setMobilePane("channels");
          }}
        >
          C
        </button>
        <div className="rail-divider" />
        {guilds.map((guild) => (
          <button
            key={guild.id}
            className={guild.id === activeGuildId ? "guild active" : "guild"}
            onClick={() => {
              setHomeOpen(false);
              selectGuild(guild.id);
              setMobilePane("channels");
            }}
            aria-label={guild.name}
          >
            {guild.name.slice(0, 2).toUpperCase()}
          </button>
        ))}
        <button
          className="guild add"
          onClick={() => void createGuild()}
          aria-label={t.createGuild}
        >
          ＋
        </button>
      </nav>
      <aside className="channel-sidebar">
        <header>
          <button
            className="mobile-back"
            onClick={() => setMobilePane("guilds")}
          >
            ‹
          </button>
          <div>
            <strong>
              {homeOpen
                ? locale === "ja"
                  ? "ホーム"
                  : "Home"
                : (activeGuild?.name ?? "CloudCord")}
            </strong>
            <small>
              {homeOpen
                ? locale === "ja"
                  ? "フレンドとダイレクトメッセージ"
                  : "Friends and direct messages"
                : (activeGuild?.description ?? t.community)}
            </small>
          </div>
          <div className="sidebar-header-actions">
            {!homeOpen && activeGuild?.ownerId === me?.id && (
              <button
                onClick={() => setGuildSettingsOpen(true)}
                aria-label={
                  locale === "ja" ? "サーバー設定" : "Server settings"
                }
              >
                ⚙
              </button>
            )}
            <LocaleSwitch locale={locale} onLocale={onLocale} />
          </div>
        </header>
        <div className="channel-list">
          {homeOpen && (
            <div className="social-actions">
              <button onClick={() => setSocialOpen(true)}>
                {locale === "ja" ? "フレンド" : "Friends"}
              </button>
              <button
                onClick={() => void sendFriendRequest()}
                aria-label="Add friend"
              >
                +
              </button>
            </div>
          )}
          <div className="section-label">
            <span>
              {homeOpen
                ? locale === "ja"
                  ? "ダイレクトメッセージ"
                  : "Direct messages"
                : t.textChannels}
            </span>
            {!homeOpen && (
              <button
                onClick={() => setChannelCreateOpen(true)}
                aria-label={
                  locale === "ja" ? "チャンネルを作成" : "Create channel"
                }
              >
                +
              </button>
            )}
          </div>
          {visibleChannels
            .filter((channel) => !channel.type.includes("VOICE"))
            .map((channel) => (
              <button
                key={channel.id}
                className={
                  channel.id === activeChannelId ? "channel active" : "channel"
                }
                onClick={() => {
                  selectChannel(channel.id);
                  setMobilePane("chat");
                }}
              >
                <span>#</span>
                {channel.name}
              </button>
            ))}
          {!homeOpen && (
            <>
              <div className="section-label">
                <span>{t.voiceChannels}</span>
              </div>
              {channels
                .filter((channel) => channel.type.includes("VOICE"))
                .map((channel) => (
                  <VoiceChannel
                    key={channel.id}
                    channel={channel}
                    locale={locale}
                  />
                ))}
            </>
          )}
        </div>
        <footer className="user-panel">
          <div className="avatar">{(me?.display_name ?? "?").slice(0, 1)}</div>
          <div>
            <strong>{me?.display_name ?? t.processing}</strong>
            <small>@{me?.username ?? ""}</small>
          </div>
          {me?.administrator && (
            <button onClick={() => setAdminOpen(true)} title={t.settings}>
              ⚙
            </button>
          )}
          <button onClick={() => void addPasskey()} title={t.addPasskey}>
            🔑
          </button>
          <button
            onClick={() => setDeveloperOpen(true)}
            title={locale === "ja" ? "Bot開発" : "Bot development"}
          >
            🤖
          </button>
          <button onClick={onSignedOut} title={t.logout}>
            ⇥
          </button>
        </footer>
      </aside>
      <section className="chat-panel">
        <header className="chat-header">
          <button
            className="mobile-menu"
            onClick={() => setMobilePane("channels")}
          >
            ☰
          </button>
          <strong>
            <span>#</span> {activeChannel?.name ?? t.chooseChannel}
          </strong>
          <p>{activeChannel?.topic}</p>
        </header>
        {error && (
          <div className="banner" role="alert">
            {error}
            <button onClick={() => setError("")}>×</button>
          </div>
        )}
        <div className="messages" aria-live="polite">
          {messages.length === 0 && activeChannel && (
            <div className="channel-intro">
              <div>#</div>
              <h2>#{activeChannel.name}</h2>
              <p>{t.channelStart}</p>
            </div>
          )}
          {messages.map((message) => (
            <MessageCard
              key={message.id}
              message={message}
              channelId={activeChannelId!}
              currentUserId={me?.id ?? ""}
              locale={locale}
              onUpdate={applyMessage}
              onDelete={discardMessage}
              onError={(reason) => setError(String(reason))}
            />
          ))}
        </div>
        <MessageComposer
          channel={activeChannel}
          guildId={homeOpen ? null : activeGuildId}
          locale={locale}
          onMessage={applyMessage}
          onThreadCreated={(thread, message) => {
            setChannels([...channels, thread]);
            selectChannel(thread.id);
            if (message) upsertMessage(message);
          }}
          onError={(reason) => setError(String(reason))}
        />
      </section>
      {adminOpen && (
        <AdminDialog locale={locale} onClose={() => setAdminOpen(false)} />
      )}
      {socialOpen && (
        <SocialDialog
          locale={locale}
          relationships={relationships}
          onClose={() => setSocialOpen(false)}
          onAdd={() => void sendFriendRequest()}
          onAccept={async (userId) => {
            await api.request(`/friend-requests/${userId}/accept`, {
              method: "POST",
              headers: { "idempotency-key": crypto.randomUUID() },
              body: "{}",
            });
            await refreshSocial();
          }}
          onBlock={async (userId) => {
            await api.request(`/blocks/${userId}`, {
              method: "PUT",
              headers: { "idempotency-key": crypto.randomUUID() },
              body: "{}",
            });
            await refreshSocial();
          }}
          onMessage={openDm}
          onError={(reason) => setError(String(reason))}
        />
      )}
      {channelCreateOpen && activeGuildId && (
        <CreateChannelDialog
          locale={locale}
          guildId={activeGuildId}
          onClose={() => setChannelCreateOpen(false)}
          onCreated={(channel) => {
            setChannels([...channels, channel]);
            selectChannel(channel.id);
            setChannelCreateOpen(false);
            setMobilePane("chat");
          }}
          onError={(reason) => setError(String(reason))}
        />
      )}
      {guildSettingsOpen && activeGuildId && (
        <GuildSettingsDialog
          locale={locale}
          guildId={activeGuildId}
          onClose={() => setGuildSettingsOpen(false)}
          onError={(reason) => setError(String(reason))}
        />
      )}
      {developerOpen && (
        <DeveloperDialog
          locale={locale}
          guilds={guilds}
          initialGuildId={activeGuildId}
          onClose={() => setDeveloperOpen(false)}
          onError={(reason) => setError(String(reason))}
        />
      )}
    </main>
  );
}

function CreateChannelDialog({
  locale,
  guildId,
  onClose,
  onCreated,
  onError,
}: {
  locale: Locale;
  guildId: string;
  onClose: () => void;
  onCreated: (channel: Channel) => void;
  onError: (reason: unknown) => void;
}) {
  const [name, setName] = useState("");
  const [topic, setTopic] = useState("");
  const [type, setType] = useState<Channel["type"]>("GUILD_TEXT");
  const [busy, setBusy] = useState(false);
  const channelTypes: Array<{ value: Channel["type"]; label: string }> = [
    { value: "GUILD_TEXT", label: locale === "ja" ? "テキスト" : "Text" },
    {
      value: "GUILD_ANNOUNCEMENT",
      label: locale === "ja" ? "アナウンス" : "Announcement",
    },
    { value: "GUILD_VOICE", label: locale === "ja" ? "ボイス" : "Voice" },
    {
      value: "GUILD_STAGE_VOICE",
      label: locale === "ja" ? "ステージ" : "Stage",
    },
    { value: "GUILD_FORUM", label: locale === "ja" ? "フォーラム" : "Forum" },
    { value: "GUILD_MEDIA", label: locale === "ja" ? "メディア" : "Media" },
    {
      value: "GUILD_CATEGORY",
      label: locale === "ja" ? "カテゴリー" : "Category",
    },
  ];
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const channel = await api.request<Channel>(
        `/guilds/${guildId}/channels`,
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({
            name: name.trim(),
            type,
            ...(topic.trim() ? { topic: topic.trim() } : {}),
          }),
        },
      );
      onCreated(channel);
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="admin-dialog create-channel-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-channel-title"
      >
        <header>
          <div>
            <p className="eyebrow">CloudCord Channels</p>
            <h2 id="create-channel-title">
              {locale === "ja" ? "チャンネルを作成" : "Create a channel"}
            </h2>
          </div>
          <button onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <form onSubmit={(event) => void submit(event)}>
          <label>
            {locale === "ja" ? "種類" : "Type"}
            <select
              value={type}
              onChange={(event) =>
                setType(event.target.value as Channel["type"])
              }
            >
              {channelTypes.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            {locale === "ja" ? "名前" : "Name"}
            <input
              required
              minLength={1}
              maxLength={100}
              value={name}
              onChange={(event) => setName(event.target.value)}
              autoFocus
            />
          </label>
          {type !== "GUILD_CATEGORY" && (
            <label>
              {locale === "ja" ? "トピック（任意）" : "Topic (optional)"}
              <textarea
                maxLength={4096}
                rows={3}
                value={topic}
                onChange={(event) => setTopic(event.target.value)}
              />
            </label>
          )}
          <div className="dialog-form-actions">
            <button type="button" className="secondary" onClick={onClose}>
              {locale === "ja" ? "キャンセル" : "Cancel"}
            </button>
            <button disabled={busy || name.trim().length === 0}>
              {busy
                ? locale === "ja"
                  ? "作成中…"
                  : "Creating…"
                : locale === "ja"
                  ? "作成"
                  : "Create"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function GuildSettingsDialog({
  locale,
  guildId,
  onClose,
  onError,
}: {
  locale: Locale;
  guildId: string;
  onClose: () => void;
  onError: (reason: unknown) => void;
}) {
  interface RoleSummary {
    id: string;
    name: string;
    permissions: string;
    managed: number;
  }
  interface EventSummary {
    id: string;
    name: string;
    startsAt: string;
    status: string;
  }
  interface RuleSummary {
    id: string;
    name: string;
    actionType: string;
    triggerMetadata: { keywords?: string[] };
  }
  interface AuditSummary {
    id: string;
    action: string;
    targetId: string | null;
    createdAt: string;
  }
  const [roles, setRoles] = useState<RoleSummary[]>([]);
  const [events, setEvents] = useState<EventSummary[]>([]);
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [audit, setAudit] = useState<AuditSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [roleName, setRoleName] = useState("");
  const [rolePermissions, setRolePermissions] = useState("68608");
  const [eventName, setEventName] = useState("");
  const [eventStart, setEventStart] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [keywords, setKeywords] = useState("");

  const refresh = useCallback(async () => {
    const [roleResult, eventResult, ruleResult, auditResult] =
      await Promise.all([
        api.request<{ roles: RoleSummary[] }>(`/guilds/${guildId}/roles`),
        api.request<{ events: EventSummary[] }>(`/guilds/${guildId}/events`),
        api.request<{ rules: RuleSummary[] }>(`/guilds/${guildId}/automod`),
        api.request<{ entries: AuditSummary[] }>(`/guilds/${guildId}/audit`),
      ]);
    setRoles(roleResult.roles);
    setEvents(eventResult.events);
    setRules(ruleResult.rules);
    setAudit(auditResult.entries);
  }, [guildId]);
  useEffect(() => {
    void refresh().catch(onError);
  }, [onError, refresh]);

  const run = async (operation: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await operation();
      await refresh();
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="admin-dialog guild-settings-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="guild-settings-title"
      >
        <header>
          <div>
            <p className="eyebrow">CloudCord Guild Control</p>
            <h2 id="guild-settings-title">
              {locale === "ja" ? "サーバー設定" : "Server settings"}
            </h2>
          </div>
          <button onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <div className="guild-settings-grid">
          <section className="settings-card">
            <h3>{locale === "ja" ? "ロール" : "Roles"}</h3>
            <ul>
              {roles.map((role) => (
                <li key={role.id}>
                  <strong>{role.name}</strong>
                  <code>{role.permissions}</code>
                  {Boolean(role.managed) && <small>managed</small>}
                </li>
              ))}
            </ul>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void run(async () => {
                  await api.request(`/guilds/${guildId}/roles`, {
                    method: "POST",
                    headers: { "idempotency-key": crypto.randomUUID() },
                    body: JSON.stringify({
                      name: roleName,
                      permissions: rolePermissions,
                    }),
                  });
                  setRoleName("");
                });
              }}
            >
              <input
                required
                maxLength={100}
                value={roleName}
                onChange={(event) => setRoleName(event.target.value)}
                placeholder={locale === "ja" ? "ロール名" : "Role name"}
              />
              <input
                required
                inputMode="numeric"
                pattern="[0-9]+"
                value={rolePermissions}
                onChange={(event) => setRolePermissions(event.target.value)}
                aria-label="Permission bitfield"
              />
              <button disabled={busy}>
                {locale === "ja" ? "追加" : "Add"}
              </button>
            </form>
          </section>
          <section className="settings-card">
            <h3>{locale === "ja" ? "イベント" : "Events"}</h3>
            <ul>
              {events.map((item) => (
                <li key={item.id}>
                  <strong>{item.name}</strong>
                  <small>
                    {new Date(item.startsAt).toLocaleString(locale)}
                  </small>
                </li>
              ))}
            </ul>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void run(async () => {
                  await api.request(`/guilds/${guildId}/events`, {
                    method: "POST",
                    headers: { "idempotency-key": crypto.randomUUID() },
                    body: JSON.stringify({
                      name: eventName,
                      startsAt: new Date(eventStart).toISOString(),
                    }),
                  });
                  setEventName("");
                  setEventStart("");
                });
              }}
            >
              <input
                required
                value={eventName}
                onChange={(event) => setEventName(event.target.value)}
                placeholder={locale === "ja" ? "イベント名" : "Event name"}
              />
              <input
                required
                type="datetime-local"
                value={eventStart}
                onChange={(event) => setEventStart(event.target.value)}
              />
              <button disabled={busy}>
                {locale === "ja" ? "予定" : "Schedule"}
              </button>
            </form>
          </section>
          <section className="settings-card">
            <h3>AutoMod</h3>
            <ul>
              {rules.map((rule) => (
                <li key={rule.id}>
                  <strong>{rule.name}</strong>
                  <small>{rule.triggerMetadata.keywords?.join(", ")}</small>
                  <button
                    className="danger-text"
                    disabled={busy}
                    onClick={() =>
                      void run(() =>
                        api.request(`/guilds/${guildId}/automod/${rule.id}`, {
                          method: "DELETE",
                          headers: { "idempotency-key": crypto.randomUUID() },
                        }),
                      )
                    }
                  >
                    {locale === "ja" ? "削除" : "Delete"}
                  </button>
                </li>
              ))}
            </ul>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void run(async () => {
                  await api.request(`/guilds/${guildId}/automod`, {
                    method: "POST",
                    headers: { "idempotency-key": crypto.randomUUID() },
                    body: JSON.stringify({
                      name: ruleName,
                      keywords: keywords.split(",").map((word) => word.trim()),
                      action: "block",
                    }),
                  });
                  setRuleName("");
                  setKeywords("");
                });
              }}
            >
              <input
                required
                value={ruleName}
                onChange={(event) => setRuleName(event.target.value)}
                placeholder={locale === "ja" ? "ルール名" : "Rule name"}
              />
              <input
                required
                value={keywords}
                onChange={(event) => setKeywords(event.target.value)}
                placeholder={
                  locale === "ja"
                    ? "禁止語（カンマ区切り）"
                    : "Keywords, comma separated"
                }
              />
              <button disabled={busy}>
                {locale === "ja" ? "追加" : "Add"}
              </button>
            </form>
          </section>
          <section className="settings-card audit-card">
            <h3>{locale === "ja" ? "監査ログ" : "Audit log"}</h3>
            <ul>
              {audit.slice(0, 25).map((entry) => (
                <li key={entry.id}>
                  <strong>{entry.action}</strong>
                  <small>
                    {entry.targetId ?? "—"} ·{" "}
                    {new Date(entry.createdAt).toLocaleString(locale)}
                  </small>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </section>
    </div>
  );
}

function DeveloperDialog({
  locale,
  guilds,
  initialGuildId,
  onClose,
  onError,
}: {
  locale: Locale;
  guilds: GuildSummary[];
  initialGuildId: string | null;
  onClose: () => void;
  onError: (reason: unknown) => void;
}) {
  interface ApplicationSummary {
    id: string;
    name: string;
    description: string;
    botUserId: string;
    intents: string;
    enabled: number;
  }
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [name, setName] = useState("");
  const [intents, setIntents] = useState("0");
  const [selectedApplication, setSelectedApplication] = useState("");
  const [selectedGuild, setSelectedGuild] = useState(initialGuildId ?? "");
  const [permissions, setPermissions] = useState("274945015872");
  const [newToken, setNewToken] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const result = await api.request<{ applications: ApplicationSummary[] }>(
      "/applications",
    );
    setApplications(result.applications);
    setSelectedApplication(
      (current) => current || result.applications[0]?.id || "",
    );
  }, []);
  useEffect(() => {
    void refresh().catch(onError);
  }, [onError, refresh]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setNewToken(null);
    try {
      const created = await api.request<{
        id: string;
        token: string;
      }>("/applications", {
        method: "POST",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ name, intents }),
      });
      setNewToken(created.token);
      setSelectedApplication(created.id);
      setName("");
      await refresh();
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  };
  const install = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await api.request(
        `/guilds/${selectedGuild}/bots/${selectedApplication}`,
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({ permissions }),
        },
      );
      setMessage(
        locale === "ja"
          ? "Botとmanaged roleをインストールしました。"
          : "Installed the Bot and its managed role.",
      );
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="admin-dialog developer-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="developer-title"
      >
        <header>
          <div>
            <p className="eyebrow">CloudCord Developer Portal</p>
            <h2 id="developer-title">
              {locale === "ja" ? "Botアプリケーション" : "Bot applications"}
            </h2>
          </div>
          <button onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        <div className="developer-grid">
          <section className="settings-card">
            <h3>{locale === "ja" ? "所有アプリ" : "Your applications"}</h3>
            <ul>
              {applications.map((application) => (
                <li key={application.id}>
                  <strong>{application.name}</strong>
                  <code>{application.id}</code>
                  <small>intents {application.intents}</small>
                </li>
              ))}
            </ul>
            <form onSubmit={(event) => void create(event)}>
              <input
                required
                maxLength={100}
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder={locale === "ja" ? "アプリ名" : "Application name"}
              />
              <input
                required
                pattern="[0-9]+"
                inputMode="numeric"
                value={intents}
                onChange={(event) => setIntents(event.target.value)}
                placeholder="Gateway intents"
              />
              <button disabled={busy}>
                {locale === "ja" ? "作成" : "Create"}
              </button>
            </form>
            {newToken && (
              <div className="token-reveal" role="status">
                <strong>
                  {locale === "ja"
                    ? "このtokenは今だけ表示されます"
                    : "This token is shown only now"}
                </strong>
                <code>{newToken}</code>
                <button
                  onClick={() => void navigator.clipboard.writeText(newToken)}
                >
                  {locale === "ja" ? "コピー" : "Copy"}
                </button>
              </div>
            )}
          </section>
          <section className="settings-card">
            <h3>
              {locale === "ja" ? "サーバーへ導入" : "Install to a server"}
            </h3>
            <form onSubmit={(event) => void install(event)}>
              <label>
                {locale === "ja" ? "アプリ" : "Application"}
                <select
                  required
                  value={selectedApplication}
                  onChange={(event) =>
                    setSelectedApplication(event.target.value)
                  }
                >
                  <option value="" disabled />
                  {applications.map((application) => (
                    <option key={application.id} value={application.id}>
                      {application.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {locale === "ja" ? "サーバー" : "Server"}
                <select
                  required
                  value={selectedGuild}
                  onChange={(event) => setSelectedGuild(event.target.value)}
                >
                  <option value="" disabled />
                  {guilds.map((guild) => (
                    <option key={guild.id} value={guild.id}>
                      {guild.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Permission bitfield
                <input
                  required
                  pattern="[0-9]+"
                  inputMode="numeric"
                  value={permissions}
                  onChange={(event) => setPermissions(event.target.value)}
                />
              </label>
              <button disabled={busy || !selectedGuild || !selectedApplication}>
                {locale === "ja" ? "導入" : "Install"}
              </button>
              <button
                type="button"
                className="secondary"
                disabled={!selectedApplication}
                onClick={() => {
                  const url = new URL("/oauth2/authorize", location.origin);
                  url.searchParams.set("client_id", selectedApplication);
                  url.searchParams.set("scope", "bot applications.commands");
                  url.searchParams.set("permissions", permissions);
                  void navigator.clipboard.writeText(url.toString());
                  setMessage(
                    locale === "ja"
                      ? "OAuth2導入URLをコピーしました。"
                      : "Copied the OAuth2 install URL.",
                  );
                }}
              >
                {locale === "ja" ? "OAuth2 URLをコピー" : "Copy OAuth2 URL"}
              </button>
            </form>
            {message && <p className="success">{message}</p>}
          </section>
        </div>
      </section>
    </div>
  );
}

function SocialDialog({
  locale,
  relationships,
  onClose,
  onAdd,
  onAccept,
  onBlock,
  onMessage,
  onError,
}: {
  locale: Locale;
  relationships: RelationshipSummary[];
  onClose: () => void;
  onAdd: () => void;
  onAccept: (userId: string) => Promise<void>;
  onBlock: (userId: string) => Promise<void>;
  onMessage: (userId: string) => Promise<void>;
  onError: (reason: unknown) => void;
}) {
  const [busyUser, setBusyUser] = useState<string | null>(null);
  const run = async (userId: string, action: (id: string) => Promise<void>) => {
    setBusyUser(userId);
    try {
      await action(userId);
    } catch (reason) {
      onError(reason);
    } finally {
      setBusyUser(null);
    }
  };
  const sections = [
    {
      title: locale === "ja" ? "フレンド" : "Friends",
      kinds: ["friend"],
    },
    {
      title: locale === "ja" ? "受信した申請" : "Incoming requests",
      kinds: ["friend_pending_incoming"],
    },
    {
      title: locale === "ja" ? "送信した申請" : "Outgoing requests",
      kinds: ["friend_pending_outgoing"],
    },
    {
      title: locale === "ja" ? "ブロック中" : "Blocked",
      kinds: ["blocked"],
    },
  ];
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="admin-dialog social-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="social-title"
      >
        <header>
          <div>
            <p className="eyebrow">CloudCord Social</p>
            <h2 id="social-title">
              {locale === "ja" ? "フレンド" : "Friends"}
            </h2>
          </div>
          <div className="dialog-actions">
            <button onClick={onAdd}>{locale === "ja" ? "追加" : "Add"}</button>
            <button onClick={onClose} aria-label="Close">
              ×
            </button>
          </div>
        </header>
        <div className="social-sections">
          {sections.map((section) => {
            const entries = relationships.filter((relationship) =>
              section.kinds.includes(relationship.kind),
            );
            return (
              <section key={section.title}>
                <h3>
                  {section.title} · {entries.length}
                </h3>
                {entries.length === 0 && (
                  <p className="empty-copy">
                    {locale === "ja"
                      ? "ここにはまだ何もありません。"
                      : "Nothing here yet."}
                  </p>
                )}
                {entries.map((relationship) => (
                  <article
                    className="relationship-row"
                    key={relationship.userId}
                  >
                    <div className="avatar">
                      {relationship.user.displayName.slice(0, 1)}
                    </div>
                    <div>
                      <strong>{relationship.user.displayName}</strong>
                      <small>@{relationship.user.username}</small>
                    </div>
                    <div className="relationship-actions">
                      {relationship.kind === "friend_pending_incoming" && (
                        <button
                          disabled={busyUser === relationship.userId}
                          onClick={() =>
                            void run(relationship.userId, onAccept)
                          }
                        >
                          {locale === "ja" ? "承認" : "Accept"}
                        </button>
                      )}
                      {relationship.kind === "friend" && (
                        <button
                          disabled={busyUser === relationship.userId}
                          onClick={() =>
                            void run(relationship.userId, onMessage)
                          }
                        >
                          {locale === "ja" ? "メッセージ" : "Message"}
                        </button>
                      )}
                      {relationship.kind !== "blocked" && (
                        <button
                          className="danger-text"
                          disabled={busyUser === relationship.userId}
                          onClick={() => void run(relationship.userId, onBlock)}
                        >
                          {locale === "ja" ? "ブロック" : "Block"}
                        </button>
                      )}
                    </div>
                  </article>
                ))}
              </section>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function MessageCard({
  message,
  channelId,
  currentUserId,
  locale,
  onUpdate,
  onDelete,
  onError,
}: {
  message: Message;
  channelId: string;
  currentUserId: string;
  locale: Locale;
  onUpdate: (message: Message) => void;
  onDelete: (id: string) => void;
  onError: (reason: unknown) => void;
}) {
  const t = labels[locale];
  const [editing, setEditing] = useState(false);
  const [content, setContent] = useState(message.content);
  const base = `/channels/${channelId}`;

  async function edit(event: FormEvent) {
    event.preventDefault();
    try {
      const updated = await api.request<Message>(
        `${base}/messages/${message.id}`,
        {
          method: "PATCH",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({ content }),
        },
      );
      onUpdate(updated);
      setEditing(false);
    } catch (reason) {
      onError(reason);
    }
  }

  async function remove() {
    if (
      !confirm(
        locale === "ja"
          ? "このメッセージを削除しますか？"
          : "Delete this message?",
      )
    )
      return;
    try {
      await api.request(`${base}/messages/${message.id}`, {
        method: "DELETE",
        headers: { "idempotency-key": crypto.randomUUID() },
      });
      onDelete(message.id);
    } catch (reason) {
      onError(reason);
    }
  }

  async function react() {
    try {
      await api.request(
        `${base}/messages/${message.id}/reactions/${encodeURIComponent("👍")}`,
        {
          method: "PUT",
          headers: { "idempotency-key": crypto.randomUUID() },
        },
      );
      const messages = await api.request<{ messages: Message[] }>(
        `${base}/messages`,
      );
      const updated = messages.messages.find((item) => item.id === message.id);
      if (updated) onUpdate(updated);
    } catch (reason) {
      onError(reason);
    }
  }

  async function pin() {
    try {
      await api.request(`${base}/pins/${message.id}`, {
        method: message.pinned ? "DELETE" : "PUT",
        headers: { "idempotency-key": crypto.randomUUID() },
      });
      onUpdate({ ...message, pinned: !message.pinned });
    } catch (reason) {
      onError(reason);
    }
  }

  async function vote(answerId: string, voted: boolean) {
    try {
      const poll = await api.request<NonNullable<Message["poll"]>>(
        `${base}/polls/${message.id}/answers/${answerId}`,
        {
          method: voted ? "DELETE" : "PUT",
          headers: { "idempotency-key": crypto.randomUUID() },
        },
      );
      onUpdate({ ...message, poll });
    } catch (reason) {
      onError(reason);
    }
  }

  return (
    <article className={message.pinned ? "message pinned" : "message"}>
      <div className="avatar small">
        {message.author.displayName.slice(0, 1)}
      </div>
      <div className="message-body">
        <header>
          <strong>{message.author.displayName}</strong>
          <time>{new Date(message.createdAt).toLocaleString(locale)}</time>
          {message.editedAt && <small>{t.edited}</small>}
          {message.pinned && <small>📌</small>}
        </header>
        {editing ? (
          <form className="message-edit" onSubmit={edit}>
            <input
              value={content}
              onChange={(event) => setContent(event.target.value)}
              maxLength={4000}
              autoFocus
            />
            <button>{t.save}</button>
            <button type="button" onClick={() => setEditing(false)}>
              {t.cancel}
            </button>
          </form>
        ) : (
          <p>{message.content}</p>
        )}
        {message.attachments.map((attachment) => (
          <a
            className="attachment"
            key={attachment.id}
            href={attachment.url}
            target="_blank"
            rel="noreferrer"
          >
            📎 {attachment.filename} · {formatBytes(attachment.size)}
          </a>
        ))}
        {message.poll && (
          <section className="poll" aria-label={message.poll.question}>
            <strong>{message.poll.question}</strong>
            {message.poll.answers.map((answer) => (
              <button
                key={answer.id}
                className={answer.meVoted ? "selected" : ""}
                onClick={() => void vote(answer.id, answer.meVoted)}
              >
                <span>{answer.text}</span>
                <small>
                  {answer.voteCount} {t.vote}
                </small>
              </button>
            ))}
          </section>
        )}
        <div className="reaction-row">
          {message.reactions.map((reaction) => (
            <span
              className={reaction.me ? "reaction mine" : "reaction"}
              key={reaction.emoji}
            >
              {reaction.emoji} {reaction.count}
            </span>
          ))}
        </div>
      </div>
      <div className="message-actions">
        <button onClick={() => void react()} aria-label="React">
          👍
        </button>
        <button onClick={() => void pin()}>{t.pin}</button>
        {message.author.id === currentUserId && (
          <>
            <button onClick={() => setEditing(true)}>{t.edit}</button>
            <button className="danger-text" onClick={() => void remove()}>
              {t.remove}
            </button>
          </>
        )}
      </div>
    </article>
  );
}

function MessageComposer({
  channel,
  guildId,
  locale,
  onMessage,
  onThreadCreated,
  onError,
}: {
  channel: Channel | undefined;
  guildId: string | null;
  locale: Locale;
  onMessage: (message: Message) => void;
  onThreadCreated: (thread: Channel, message: Message | null) => void;
  onError: (reason: unknown) => void;
}) {
  const t = labels[locale];
  const [content, setContent] = useState("");
  const [threadName, setThreadName] = useState("");
  const [busy, setBusy] = useState(false);
  const [attachmentIds, setAttachmentIds] = useState<string[]>([]);
  const [attachmentNames, setAttachmentNames] = useState<string[]>([]);
  const [pollOpen, setPollOpen] = useState(false);
  const [pollQuestion, setPollQuestion] = useState("");
  const [pollAnswers, setPollAnswers] = useState(["", ""]);
  const fileInput = useRef<HTMLInputElement | null>(null);

  async function upload(file: File) {
    if (!channel || !guildId) return;
    setBusy(true);
    try {
      const ticket = await api.request<{ id: string; uploadUrl: string }>(
        "/uploads",
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({
            filename: file.name,
            contentType: file.type || "application/octet-stream",
            size: file.size,
            guildId,
          }),
        },
      );
      await api.request(ticket.uploadUrl.replace(/^\/api\/v1/, ""), {
        method: "PUT",
        headers: {
          "content-type": file.type || "application/octet-stream",
          "idempotency-key": crypto.randomUUID(),
        },
        body: file,
      });
      setAttachmentIds((items) => [...items, ticket.id]);
      setAttachmentNames((items) => [...items, file.name]);
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    const validPoll =
      pollOpen &&
      pollQuestion.trim() &&
      pollAnswers.every((answer) => answer.trim());
    const forumPost = ["GUILD_FORUM", "GUILD_MEDIA"].includes(
      channel?.type ?? "",
    );
    if (
      !channel ||
      (forumPost && !threadName.trim()) ||
      (!content.trim() && attachmentIds.length === 0 && !validPoll) ||
      busy
    )
      return;
    setBusy(true);
    try {
      if (forumPost) {
        if (attachmentIds.length > 0 || validPoll)
          throw new Error(
            locale === "ja"
              ? "Forumの最初の投稿では添付と投票をまだ利用できません。"
              : "Attachments and polls are not yet available in the first forum post.",
          );
        const result = await api.request<{
          thread: Channel;
          message: Message | null;
        }>(`/channels/${channel.id}/threads`, {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({
            name: threadName.trim(),
            content: content.trim(),
            autoArchiveMinutes: 1440,
          }),
        });
        onThreadCreated(result.thread, result.message);
        setThreadName("");
        setContent("");
        return;
      }
      const message = await api.request<Message>(
        `/channels/${channel.id}/messages`,
        {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({
            content: content.trim(),
            attachmentIds,
            ...(validPoll
              ? {
                  poll: {
                    question: pollQuestion.trim(),
                    answers: pollAnswers.map((answer) => answer.trim()),
                    durationHours: 24,
                    allowMultiselect: false,
                  },
                }
              : {}),
          }),
        },
      );
      onMessage(message);
      setContent("");
      setAttachmentIds([]);
      setAttachmentNames([]);
      setPollOpen(false);
      setPollQuestion("");
      setPollAnswers(["", ""]);
    } catch (reason) {
      onError(reason);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="composer-shell">
      {channel && ["GUILD_FORUM", "GUILD_MEDIA"].includes(channel.type) && (
        <div className="forum-title-composer">
          <input
            value={threadName}
            onChange={(event) => setThreadName(event.target.value)}
            maxLength={100}
            placeholder={
              locale === "ja" ? "新しい投稿のタイトル" : "New post title"
            }
          />
        </div>
      )}
      {attachmentNames.length > 0 && (
        <div className="composer-chips">
          {attachmentNames.map((name) => (
            <span key={name}>📎 {name}</span>
          ))}
        </div>
      )}
      {pollOpen && (
        <div className="poll-composer">
          <input
            value={pollQuestion}
            onChange={(event) => setPollQuestion(event.target.value)}
            placeholder={locale === "ja" ? "質問" : "Question"}
            maxLength={300}
          />
          {pollAnswers.map((answer, index) => (
            <input
              key={index}
              value={answer}
              onChange={(event) =>
                setPollAnswers((items) =>
                  items.map((item, itemIndex) =>
                    itemIndex === index ? event.target.value : item,
                  ),
                )
              }
              placeholder={`${locale === "ja" ? "選択肢" : "Option"} ${index + 1}`}
              maxLength={55}
            />
          ))}
        </div>
      )}
      <form className="composer" onSubmit={send}>
        <input
          ref={fileInput}
          className="visually-hidden"
          type="file"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void upload(file);
            event.currentTarget.value = "";
          }}
        />
        <button
          type="button"
          aria-label={t.attach}
          onClick={() => fileInput.current?.click()}
        >
          ＋
        </button>
        <button
          type="button"
          aria-label={t.poll}
          onClick={() => setPollOpen((open) => !open)}
        >
          ◫
        </button>
        <input
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder={
            channel
              ? `#${channel.name} · ${t.messagePlaceholder}`
              : t.chooseChannel
          }
          disabled={!channel}
          maxLength={4000}
        />
        <button type="submit" disabled={!channel || busy} aria-label={t.submit}>
          ➤
        </button>
      </form>
    </div>
  );
}

function AdminDialog({
  locale,
  onClose,
}: {
  locale: Locale;
  onClose: () => void;
}) {
  interface Overview {
    users: number;
    activeSessions: number;
    bots: number;
    media: { objects: number; bytes: number };
    voiceUsage30d: {
      participantHours: number;
      estimatedSourceGb: number;
      estimatedGbPerParticipantHour: number;
      warningThreshold: number;
      warning: boolean;
    };
    shardPools: { identity: number; social: number; guild: number };
    settings: Record<string, string>;
  }
  const [overview, setOverview] = useState<Overview | null>(null);
  const [fileLimit, setFileLimit] = useState("52428800");
  const [voiceWarning, setVoiceWarning] = useState("0.15");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    void api.request<Overview>("/admin/overview").then((result) => {
      setOverview(result);
      setFileLimit(result.settings["upload.file.bytes"] ?? "52428800");
      setVoiceWarning(result.settings["voice.warning_gb_per_hour"] ?? "0.15");
    });
  }, []);
  async function save(event: FormEvent) {
    event.preventDefault();
    await api.request("/admin/settings", {
      method: "PATCH",
      headers: { "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify({
        values: {
          "upload.file.bytes": fileLimit,
          "voice.warning_gb_per_hour": voiceWarning,
        },
        reason,
      }),
    });
    setMessage(locale === "ja" ? "保存しました" : "Saved");
  }
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="admin-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="admin-title"
      >
        <header>
          <div>
            <p className="eyebrow">INSTANCE CONTROL</p>
            <h2 id="admin-title">
              {locale === "ja" ? "管理コンソール" : "Administration"}
            </h2>
          </div>
          <button onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>
        {!overview ? (
          <p>{labels[locale].processing}</p>
        ) : (
          <>
            <div className="metrics">
              <div>
                <strong>{overview.users}</strong>
                <span>Users</span>
              </div>
              <div>
                <strong>{overview.activeSessions}</strong>
                <span>Sessions</span>
              </div>
              <div>
                <strong>{overview.bots}</strong>
                <span>Bots</span>
              </div>
              <div>
                <strong>{formatBytes(overview.media.bytes)}</strong>
                <span>R2 media</span>
              </div>
              <div
                className={
                  overview.voiceUsage30d.warning ? "metric-warning" : ""
                }
              >
                <strong>
                  {overview.voiceUsage30d.estimatedGbPerParticipantHour.toFixed(
                    3,
                  )}{" "}
                  GB
                </strong>
                <span>Estimated live source / participant-hour</span>
              </div>
            </div>
            <p className="muted">
              D1: Identity {overview.shardPools.identity} · Social{" "}
              {overview.shardPools.social} · Guild {overview.shardPools.guild}
            </p>
            <form onSubmit={(event) => void save(event)}>
              <label>
                {locale === "ja"
                  ? "ファイル上限（bytes）"
                  : "File limit (bytes)"}
                <input
                  value={fileLimit}
                  onChange={(event) => setFileLimit(event.target.value)}
                  inputMode="numeric"
                  pattern="[0-9]+"
                />
              </label>
              <label>
                {locale === "ja"
                  ? "VC警告値（GB/参加者時間）"
                  : "VC warning (GB / participant-hour)"}
                <input
                  value={voiceWarning}
                  onChange={(event) => setVoiceWarning(event.target.value)}
                  inputMode="decimal"
                  pattern="[0-9]+([.][0-9]+)?"
                  required
                />
              </label>
              <label>
                {locale === "ja" ? "変更理由" : "Reason for change"}
                <input
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  minLength={4}
                  required
                />
              </label>
              <button className="primary">{labels[locale].save}</button>
              {message && <p className="success">{message}</p>}
            </form>
          </>
        )}
      </section>
    </div>
  );
}

function VoiceChannel({
  channel,
  locale,
}: {
  channel: Channel;
  locale: Locale;
}) {
  const t = labels[locale];
  const voice = useVoice(channel.id);
  return (
    <div className="voice-channel">
      <button className="channel" onClick={() => void voice.toggle()}>
        <span>◖</span>
        {channel.name}
        <i>{voice.connected ? t.connected : ""}</i>
      </button>
      {voice.connected && (
        <div className="voice-controls">
          <button
            className={voice.muted ? "danger" : ""}
            onClick={voice.toggleMute}
          >
            {voice.muted ? t.muted : t.microphone}
          </button>
          <button onClick={() => void voice.toggleCamera()}>{t.camera}</button>
          <button onClick={() => void voice.shareScreen()}>{t.screen}</button>
          <button className="danger" onClick={() => void voice.disconnect()}>
            {t.disconnect}
          </button>
        </div>
      )}
    </div>
  );
}

function useVoice(channelId: string) {
  const [connected, setConnected] = useState(false);
  const [muted, setMuted] = useState(false);
  const peer = useRef<RTCPeerConnection | null>(null);
  const media = useRef<MediaStream | null>(null);
  const control = useRef<WebSocket | null>(null);
  const sessionId = useRef<string | null>(null);
  const analyserTimer = useRef<number | null>(null);
  const audioContext = useRef<AudioContext | null>(null);
  const remoteAudio = useRef(new Map<string, HTMLAudioElement>());
  const published = useRef(
    new Map<
      string,
      {
        trackName: string;
        mid: string | null;
        label: "microphone" | "camera" | "screen";
      }
    >(),
  );
  const subscribed = useRef(new Map<string, string>());
  const lastSubscriptionUpdate = useRef(0);
  const negotiationQueue = useRef<Promise<void>>(Promise.resolve());

  type TrackRequest = {
    location: "local" | "remote";
    transceiver?: RTCRtpTransceiver;
    mid?: string;
    trackName: string;
    sessionId?: string;
    kind?: "audio" | "video";
    label?: "microphone" | "camera" | "screen";
    simulcast?: {
      preferredRid: string;
      priorityOrdering: "asciibetical";
      ridNotAvailable: "asciibetical";
    };
  };

  const negotiate = useCallback(
    (tracks: TrackRequest[]) => {
      const operation = negotiationQueue.current.then(async () => {
        const pc = peer.current;
        const currentSession = sessionId.current;
        if (!pc || !currentSession || tracks.length === 0) return;
        const localTracks = tracks.some((track) => track.location === "local");
        let description: RTCSessionDescriptionInit | undefined;
        if (localTracks) {
          const offer = await pc.createOffer();
          description = {
            type: offer.type,
            sdp: enableOpusDtx(offer.sdp) ?? "",
          };
          await pc.setLocalDescription(description);
        }
        const result = await api.request<{
          sessionDescription?: RTCSessionDescriptionInit;
          requiresImmediateRenegotiation?: boolean;
          tracks?: Array<{
            location?: string;
            mid?: string;
            sessionId?: string;
            trackName?: string;
          }>;
        }>(`/realtime/sessions/${currentSession}/tracks`, {
          method: "POST",
          headers: { "idempotency-key": crypto.randomUUID() },
          body: JSON.stringify({
            channelId,
            sessionDescription: description,
            tracks: tracks.map((track) => ({
              location: track.location,
              mid: track.transceiver?.mid ?? track.mid,
              trackName: track.trackName,
              sessionId: track.sessionId,
              kind: track.kind,
              label: track.label,
              simulcast: track.simulcast,
            })),
          }),
        });
        if (result.sessionDescription?.type === "answer") {
          await pc.setRemoteDescription(result.sessionDescription);
        } else if (result.sessionDescription?.type === "offer") {
          await pc.setRemoteDescription(result.sessionDescription);
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          await api.request(
            `/realtime/sessions/${currentSession}/renegotiate`,
            {
              method: "PUT",
              headers: { "idempotency-key": crypto.randomUUID() },
              body: JSON.stringify({
                channelId,
                sessionDescription: answer,
              }),
            },
          );
        }
        for (const requested of tracks) {
          const resolved = result.tracks?.find(
            (track) =>
              track.trackName === requested.trackName &&
              (!requested.sessionId || track.sessionId === requested.sessionId),
          );
          const mid = resolved?.mid ?? requested.transceiver?.mid;
          if (requested.location === "remote" && mid)
            subscribed.current.set(
              `${requested.sessionId}:${requested.trackName}`,
              mid,
            );
        }
      });
      negotiationQueue.current = operation.catch(() => undefined);
      return operation;
    },
    [channelId],
  );

  const closeTracks = useCallback(
    async (trackNames: string[], mids: string[]) => {
      const currentSession = sessionId.current;
      if (!currentSession || (trackNames.length === 0 && mids.length === 0))
        return;
      await api.request(`/realtime/sessions/${currentSession}/tracks`, {
        method: "DELETE",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ channelId, trackNames, mids }),
      });
    },
    [channelId],
  );

  const connect = useCallback(async () => {
    await api.request(`/voice/${channelId}/join`, {
      method: "POST",
      headers: { "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify({ muted: false, deafened: false, camera: false }),
    });
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: {
        channelCount: 1,
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
      video: false,
    });
    media.current = stream;
    control.current = await api.websocket(`/voice/${channelId}/control`);
    const session = await api.request<{ sessionId: string }>(
      "/realtime/sessions",
      {
        method: "POST",
        headers: { "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ channelId }),
      },
    );
    sessionId.current = session.sessionId;
    const pc = new RTCPeerConnection({ bundlePolicy: "max-bundle" });
    peer.current = pc;
    const transceiver = pc.addTransceiver(stream.getAudioTracks()[0]!, {
      direction: "sendrecv",
      streams: [stream],
      sendEncodings: [{ maxBitrate: 32_000 }],
    });
    const codecs = RTCRtpSender.getCapabilities("audio")?.codecs.filter(
      (codec) => codec.mimeType.toLowerCase() === "audio/opus",
    );
    if (codecs?.length) transceiver.setCodecPreferences(codecs);
    pc.addEventListener("track", (event) => {
      const audio = new Audio();
      audio.autoplay = true;
      audio.srcObject = event.streams[0] ?? new MediaStream([event.track]);
      remoteAudio.current.set(event.track.id, audio);
      event.track.addEventListener("ended", () => {
        audio.pause();
        remoteAudio.current.delete(event.track.id);
      });
    });
    const microphoneName = `audio-${crypto.randomUUID()}`;
    await negotiate([
      {
        location: "local",
        transceiver,
        trackName: microphoneName,
        kind: "audio",
        label: "microphone",
      },
    ]);
    const context = new AudioContext();
    audioContext.current = context;
    const source = context.createMediaStreamSource(stream);
    const analyser = context.createAnalyser();
    analyser.fftSize = 256;
    source.connect(analyser);
    const samples = new Uint8Array(analyser.frequencyBinCount);
    analyserTimer.current = window.setInterval(() => {
      analyser.getByteFrequencyData(samples);
      const level =
        samples.reduce((sum, value) => sum + value, 0) / samples.length / 255;
      if (control.current?.readyState === WebSocket.OPEN)
        control.current.send(
          JSON.stringify({ op: 3, data: { level, speaking: level > 0.08 } }),
        );
    }, 250);
    control.current.addEventListener("message", (event) => {
      if (typeof event.data !== "string") return;
      try {
        const message = JSON.parse(event.data) as {
          op?: number;
          data?: {
            publishers?: Array<{
              sessionId: string;
              tracks: Array<{
                trackName: string;
                kind: "audio" | "video";
                label: "microphone" | "camera" | "screen";
              }>;
            }>;
          };
        };
        if (message.op !== 5 || !message.data?.publishers) return;
        const now = Date.now();
        if (now - lastSubscriptionUpdate.current < 500) return;
        lastSubscriptionUpdate.current = now;
        const wanted = new Map<string, TrackRequest>();
        for (const publisher of message.data.publishers)
          for (const track of publisher.tracks) {
            const key = `${publisher.sessionId}:${track.trackName}`;
            const request: TrackRequest = {
              location: "remote",
              sessionId: publisher.sessionId,
              trackName: track.trackName,
              kind: track.kind,
              label: track.label,
            };
            if (track.kind === "video")
              request.simulcast = {
                preferredRid: track.label === "screen" ? "f" : "h",
                priorityOrdering: "asciibetical",
                ridNotAvailable: "asciibetical",
              };
            wanted.set(key, request);
          }
        const stale = [...subscribed.current.entries()].filter(
          ([key]) => !wanted.has(key),
        );
        if (stale.length > 0) {
          for (const [key] of stale) subscribed.current.delete(key);
          void closeTracks(
            [],
            stale.map(([, mid]) => mid),
          );
        }
        const additions = [...wanted.entries()]
          .filter(([key]) => !subscribed.current.has(key))
          .map(([, track]) => track);
        if (additions.length > 0) void negotiate(additions);
      } catch {
        // Ignore malformed control frames; the socket remains usable.
      }
    });
    setConnected(true);
  }, [channelId, closeTracks, negotiate]);

  const disconnect = useCallback(async () => {
    if (analyserTimer.current !== null) clearInterval(analyserTimer.current);
    media.current?.getTracks().forEach((track) => track.stop());
    await audioContext.current?.close().catch(() => undefined);
    audioContext.current = null;
    for (const audio of remoteAudio.current.values()) audio.pause();
    remoteAudio.current.clear();
    peer.current?.close();
    control.current?.close(1000, "Left voice");
    await api
      .request(`/voice/${channelId}`, { method: "DELETE" })
      .catch(() => undefined);
    setConnected(false);
    setMuted(false);
    sessionId.current = null;
    published.current.clear();
    subscribed.current.clear();
  }, [channelId]);

  useEffect(
    () => () => {
      if (analyserTimer.current !== null) clearInterval(analyserTimer.current);
      media.current?.getTracks().forEach((track) => track.stop());
      void audioContext.current?.close();
      for (const audio of remoteAudio.current.values()) audio.pause();
      peer.current?.close();
      control.current?.close();
    },
    [],
  );

  return {
    connected,
    muted,
    toggle: () => (connected ? disconnect() : connect()),
    disconnect,
    toggleMute: () => {
      const next = !muted;
      media.current?.getAudioTracks().forEach((track) => {
        track.enabled = !next;
      });
      setMuted(next);
      control.current?.send(JSON.stringify({ op: 4, data: { muted: next } }));
    },
    toggleCamera: async () => {
      if (!peer.current || !media.current) return;
      const existing = media.current
        .getVideoTracks()
        .find((track) => published.current.get(track.id)?.label === "camera");
      if (existing) {
        const metadata = published.current.get(existing.id);
        existing.stop();
        media.current.removeTrack(existing);
        if (metadata) {
          published.current.delete(existing.id);
          await closeTracks(
            [metadata.trackName],
            metadata.mid ? [metadata.mid] : [],
          );
        }
        control.current?.send(
          JSON.stringify({ op: 4, data: { camera: false, muted } }),
        );
        return;
      }
      const camera = await navigator.mediaDevices.getUserMedia({
        video: { width: 1280, height: 720, frameRate: 30 },
      });
      const track = camera.getVideoTracks()[0]!;
      media.current.addTrack(track);
      const transceiver = peer.current.addTransceiver(track, {
        direction: "sendonly",
        streams: [media.current],
        sendEncodings: [
          { rid: "q", scaleResolutionDownBy: 4, maxBitrate: 150_000 },
          { rid: "h", scaleResolutionDownBy: 2, maxBitrate: 500_000 },
          { rid: "f", scaleResolutionDownBy: 1, maxBitrate: 1_500_000 },
        ],
      });
      const trackName = `camera-${crypto.randomUUID()}`;
      await negotiate([
        {
          location: "local",
          transceiver,
          trackName,
          kind: "video",
          label: "camera",
        },
      ]);
      published.current.set(track.id, {
        trackName,
        mid: transceiver.mid,
        label: "camera",
      });
      control.current?.send(
        JSON.stringify({ op: 4, data: { camera: true, muted } }),
      );
    },
    shareScreen: async () => {
      if (!peer.current || !media.current) return;
      const display = await navigator.mediaDevices.getDisplayMedia({
        video: { width: 1920, height: 1080, frameRate: 30 },
        audio: false,
      });
      const track = display.getVideoTracks()[0]!;
      media.current.addTrack(track);
      const transceiver = peer.current.addTransceiver(track, {
        direction: "sendonly",
        streams: [media.current],
        sendEncodings: [
          { rid: "h", scaleResolutionDownBy: 2, maxBitrate: 900_000 },
          { rid: "f", scaleResolutionDownBy: 1, maxBitrate: 3_000_000 },
        ],
      });
      const trackName = `screen-${crypto.randomUUID()}`;
      await negotiate([
        {
          location: "local",
          transceiver,
          trackName,
          kind: "video",
          label: "screen",
        },
      ]);
      published.current.set(track.id, {
        trackName,
        mid: transceiver.mid,
        label: "screen",
      });
      control.current?.send(
        JSON.stringify({ op: 4, data: { screen: true, muted } }),
      );
      track.addEventListener("ended", () => {
        const metadata = published.current.get(track.id);
        if (metadata) {
          published.current.delete(track.id);
          void closeTracks(
            [metadata.trackName],
            metadata.mid ? [metadata.mid] : [],
          );
        }
        control.current?.send(
          JSON.stringify({ op: 4, data: { screen: false, muted } }),
        );
      });
    },
  };
}

function enableOpusDtx(sdp: string | undefined): string | undefined {
  if (!sdp) return sdp;
  const match = sdp.match(/^a=rtpmap:(\d+) opus\/48000/imu);
  if (!match) return sdp;
  const payload = match[1];
  const fmtp = new RegExp(`^a=fmtp:${payload} (.*)$`, "imu");
  if (fmtp.test(sdp))
    return sdp.replace(fmtp, (line) =>
      line.includes("usedtx=1") ? line : `${line};usedtx=1;stereo=0`,
    );
  return sdp.replace(
    match[0],
    `${match[0]}\r\na=fmtp:${payload} usedtx=1;stereo=0`,
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}
