import {
  CONNECTOR_API,
  type Connector,
  type ConnectorCtx,
  type ConnectorEvent,
  type ReplyRequest,
} from "transit-connector-kit";

type TokenCache = { accessToken: string; expiresAt: number };
type GmailHeader = { name?: string; value?: string };
type GmailPart = {
  mimeType?: string;
  body?: { data?: string };
  parts?: GmailPart[];
};
type GmailMessage = {
  id: string;
  threadId: string;
  labelIds?: string[];
  snippet?: string;
  payload?: GmailPart & { headers?: GmailHeader[] };
};

function pollMilliseconds(config: Record<string, string>): number {
  const seconds = Number.parseInt(config.poll_seconds || "60", 10);
  return Math.max(30, Number.isFinite(seconds) ? seconds : 60) * 1_000;
}

async function accessToken(ctx: ConnectorCtx): Promise<string> {
  const cached = await ctx.storage.get<TokenCache>("token");
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.accessToken;
  const clientID = ctx.config.client_id;
  const clientSecret = ctx.config.client_secret;
  const refreshToken = ctx.config.refresh_token;
  if (!clientID || !clientSecret || !refreshToken) {
    throw new Error("Gmail OAuth credentials are not configured");
  }
  const response = await ctx.fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientID,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });
  const body = (await response.json()) as {
    access_token?: string;
    expires_in?: number;
    error_description?: string;
  };
  if (!response.ok || !body.access_token) {
    throw new Error(body.error_description || `Gmail token refresh failed (${response.status})`);
  }
  const lifetime = Math.min(body.expires_in ?? 3_600, 3_300) * 1_000;
  await ctx.storage.put("token", {
    accessToken: body.access_token,
    expiresAt: Date.now() + lifetime,
  } satisfies TokenCache);
  return body.access_token;
}

async function gmailFetch(
  ctx: ConnectorCtx,
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const token = await accessToken(ctx);
  const email = ctx.config.email;
  if (!email) throw new Error("Gmail email is not configured");
  return ctx.fetch(`https://gmail.googleapis.com/gmail/v1/users/${encodeURIComponent(email)}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      ...(init?.headers ?? {}),
    },
  });
}

function header(message: GmailMessage, name: string): string {
  return (
    message.payload?.headers?.find(
      (candidate) => candidate.name?.toLowerCase() === name.toLowerCase(),
    )?.value ?? ""
  );
}

function decodeBase64Url(value: string): string {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = atob(padded);
  return new TextDecoder().decode(
    Uint8Array.from(binary, (character) => character.charCodeAt(0)),
  );
}

function textBody(part: GmailPart | undefined): string {
  if (!part) return "";
  if (part.mimeType === "text/plain" && part.body?.data) {
    return decodeBase64Url(part.body.data);
  }
  for (const child of part.parts ?? []) {
    const text = textBody(child);
    if (text) return text;
  }
  return part.body?.data ? decodeBase64Url(part.body.data) : "";
}

function csv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function labelsAllowed(message: GmailMessage, config: Record<string, string>): boolean {
  const labels = new Set(message.labelIds ?? []);
  const required = csv(config.labels_require);
  const excluded = csv(config.labels_exclude);
  return required.every((label) => labels.has(label)) && !excluded.some((label) => labels.has(label));
}

async function fetchMessage(ctx: ConnectorCtx, id: string): Promise<GmailMessage> {
  const response = await gmailFetch(ctx, `/messages/${encodeURIComponent(id)}?format=full`);
  if (!response.ok) throw new Error(`Gmail message get failed (${response.status})`);
  return response.json<GmailMessage>();
}

async function normalizeMessage(
  ctx: ConnectorCtx,
  message: GmailMessage,
): Promise<ConnectorEvent | null> {
  if (!labelsAllowed(message, ctx.config)) return null;
  const from = header(message, "From") || "unknown";
  const subject = header(message, "Subject") || "(no subject)";
  const body = textBody(message.payload).trim() || message.snippet || "(empty email)";
  const fromEmail = from.match(/<([^>]+)>/u)?.[1] ?? from;
  return {
    eventKey: `${ctx.config.email}:${message.id}`,
    conversationId: message.threadId,
    user: from,
    trigger: "email",
    content: `New email from ${from}\nSubject: ${subject}\n\n${body}`,
    meta: {
      gmail_id: message.id,
      thread_id: message.threadId,
      from_email: fromEmail,
      subject,
      message_id: header(message, "Message-ID"),
    },
  };
}

async function profileHistoryID(ctx: ConnectorCtx): Promise<string> {
  const response = await gmailFetch(ctx, "/profile");
  const profile = (await response.json()) as { historyId?: string };
  if (!response.ok || !profile.historyId) {
    throw new Error(`Gmail profile failed (${response.status})`);
  }
  return profile.historyId;
}

async function wake(ctx: ConnectorCtx): Promise<void> {
  try {
    const watermark = await ctx.storage.get<string>("history_id");
    if (!watermark) {
      await ctx.storage.put("history_id", await profileHistoryID(ctx));
      ctx.setStatus({ state: "polling", detail: "watermark initialized" });
      return;
    }

    let pageToken = "";
    let latest = watermark;
    do {
      const query = new URLSearchParams({
        startHistoryId: watermark,
        historyTypes: "messageAdded",
      });
      if (pageToken) query.set("pageToken", pageToken);
      const response = await gmailFetch(ctx, `/history?${query}`);
      if (response.status === 404) {
        await ctx.storage.put("history_id", await profileHistoryID(ctx));
        ctx.log("warn", "Gmail history expired; watermark reset and gap may exist");
        return;
      }
      const body = (await response.json()) as {
        history?: Array<{
          id?: string;
          messagesAdded?: Array<{ message?: { id?: string } }>;
        }>;
        historyId?: string;
        nextPageToken?: string;
      };
      if (!response.ok) throw new Error(`Gmail history failed (${response.status})`);
      for (const history of body.history ?? []) {
        for (const added of history.messagesAdded ?? []) {
          if (!added.message?.id) continue;
          const event = await normalizeMessage(
            ctx,
            await fetchMessage(ctx, added.message.id),
          );
          if (event) await ctx.ingest(event);
        }
        if (history.id) latest = history.id;
      }
      if (body.historyId) latest = body.historyId;
      pageToken = body.nextPageToken ?? "";
    } while (pageToken);
    await ctx.storage.put("history_id", latest);
    ctx.setStatus({ state: "polling" });
  } finally {
    ctx.scheduleWake(pollMilliseconds(ctx.config));
  }
}

function base64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function postReply(ctx: ConnectorCtx, request: ReplyRequest): Promise<void> {
  const to = request.event.meta?.from_email;
  if (!to) throw new Error("Gmail event has no reply address");
  const originalSubject = request.event.meta?.subject ?? "";
  const subject = /^re:/iu.test(originalSubject) ? originalSubject : `Re: ${originalSubject}`;
  const inReplyTo = request.event.meta?.message_id;
  const raw = [
    `From: ${ctx.config.email}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    ...(inReplyTo ? [`In-Reply-To: ${inReplyTo}`, `References: ${inReplyTo}`] : []),
    "Content-Type: text/plain; charset=UTF-8",
    "MIME-Version: 1.0",
    "",
    request.message,
  ].join("\r\n");
  const response = await gmailFetch(ctx, "/messages/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      raw: base64Url(raw),
      threadId: request.event.meta?.thread_id ?? request.conversationId,
    }),
  });
  if (!response.ok) throw new Error(`Gmail reply failed (${response.status})`);
}

const gmail = {
  api: CONNECTOR_API,
  name: "gmail",
  mode: "poll",
  configFields: [
    { key: "email", label: "Email", required: true },
    { key: "client_id", label: "OAuth client ID", required: true },
    { key: "client_secret", label: "OAuth client secret", secret: true, required: true },
    { key: "refresh_token", label: "OAuth refresh token", secret: true, required: true },
    { key: "labels_require", label: "Required labels" },
    { key: "labels_exclude", label: "Excluded labels" },
    { key: "poll_seconds", label: "Poll seconds", placeholder: "60" },
    { key: "instructions", label: "Agent instructions" },
  ],
  start: wake,
  wake,
  postReply,
} satisfies Connector;

export { normalizeMessage as normalizeGmailMessage };
export default gmail;
