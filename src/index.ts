import {
  CONNECTOR_API,
  type Connector,
  type ConnectorAttachment,
  type ConnectorCtx,
  type ConnectorEvent,
  type ReplyRequest,
} from "transit-connector-kit";

type TokenCache = { accessToken: string; expiresAt: number };
type GmailHeader = { name?: string; value?: string };
type GmailPart = {
  mimeType?: string;
  filename?: string;
  body?: {
    data?: string;
    attachmentId?: string;
    size?: number;
  };
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
type ServiceAccountKey = { client_email?: unknown; private_key?: unknown };
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GMAIL_SCOPE = "https://mail.google.com/";

function tokenCacheKey(email: string): string {
  return `token:${email}`;
}

function base64UrlBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value.replaceAll(/\s/g, ""));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseServiceAccountKey(value: string): { clientEmail: string; privateKey: string } {
  let parsed: ServiceAccountKey;
  try {
    parsed = JSON.parse(value) as ServiceAccountKey;
  } catch {
    throw new Error("Gmail service-account key is invalid: not valid JSON");
  }
  if (typeof parsed.client_email !== "string" || !parsed.client_email) {
    throw new Error("Gmail service-account key is invalid: missing client_email");
  }
  if (typeof parsed.private_key !== "string" || !parsed.private_key) {
    throw new Error("Gmail service-account key is invalid: missing private_key");
  }
  return { clientEmail: parsed.client_email, privateKey: parsed.private_key };
}

async function serviceAccountAssertion(saKey: string, email: string): Promise<string> {
  const { clientEmail, privateKey } = parseServiceAccountKey(saKey);
  const keyData = privateKey
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replaceAll(/\s/g, "");
  if (!keyData) throw new Error("Gmail service-account key is invalid: empty private_key");

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      base64ToBytes(keyData),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch {
    throw new Error("Gmail service-account key is invalid: private_key is not PKCS#8 RSA");
  }

  const now = Math.floor(Date.now() / 1_000);
  const unsigned = [
    base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" })),
    base64Url(
      JSON.stringify({
        iss: clientEmail,
        sub: email,
        aud: GOOGLE_TOKEN_ENDPOINT,
        scope: GMAIL_SCOPE,
        iat: now,
        exp: now + 3_600,
      }),
    ),
  ].join(".");
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(unsigned),
  );
  return `${unsigned}.${base64UrlBytes(new Uint8Array(signature))}`;
}

async function readTokenResponse(response: Response, operation: string): Promise<{
  accessToken: string;
  expiresIn: number;
}> {
  const body = (await response.json()) as {
    access_token?: string;
    expires_in?: number;
    error_description?: string;
  };
  if (!response.ok || !body.access_token) {
    throw new Error(body.error_description || `${operation} (${response.status})`);
  }
  return { accessToken: body.access_token, expiresIn: body.expires_in ?? 3_600 };
}

async function refreshCallerToken(ctx: ConnectorCtx): Promise<{
  accessToken: string;
  expiresIn: number;
}> {
  const clientID = ctx.config.client_id;
  const clientSecret = ctx.config.client_secret;
  const refreshToken = ctx.config.refresh_token;
  if (!clientID || !clientSecret || !refreshToken) {
    throw new Error("Gmail OAuth credentials are not configured");
  }
  return readTokenResponse(
    await ctx.fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientID,
        client_secret: clientSecret,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
      }),
    }),
    "Gmail token refresh failed",
  );
}

async function keylessServiceAccountToken(
  ctx: ConnectorCtx,
  callerToken: string,
  serviceAccount: string,
  email: string,
): Promise<{ accessToken: string; expiresIn: number }> {
  const now = Math.floor(Date.now() / 1_000);
  const payload = JSON.stringify({
    iss: serviceAccount,
    sub: email,
    aud: GOOGLE_TOKEN_ENDPOINT,
    scope: GMAIL_SCOPE,
    iat: now,
    exp: now + 3_600,
  });
  const signed = await ctx.fetch(
    `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${encodeURIComponent(
      serviceAccount,
    )}:signJwt`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${callerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ payload }),
    },
  );
  const signedBody = (await signed.json()) as {
    signedJwt?: string;
    error?: { message?: string };
  };
  if (!signed.ok || !signedBody.signedJwt) {
    throw new Error(
      signedBody.error?.message ||
        `Gmail IAM signJwt failed (${signed.status})`,
    );
  }
  return readTokenResponse(
    await ctx.fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: signedBody.signedJwt,
      }),
    }),
    "Gmail keyless service-account token exchange failed",
  );
}

async function accessToken(ctx: ConnectorCtx): Promise<string> {
  const email = ctx.config.email;
  if (!email) throw new Error("Gmail email is not configured");
  const cacheKey = tokenCacheKey(email);
  const cached = await ctx.storage.get<TokenCache>(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.accessToken;

  const saKey = ctx.config.sa_key;
  let token: { accessToken: string; expiresIn: number };
  if (saKey) {
    const assertion = await serviceAccountAssertion(saKey, email);
    token = await readTokenResponse(
      await ctx.fetch(GOOGLE_TOKEN_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
          assertion,
        }),
      }),
      "Gmail service-account token exchange failed",
    );
  } else {
    token = await refreshCallerToken(ctx);
    if (ctx.config.dwd_service_account) {
      token = await keylessServiceAccountToken(
        ctx,
        token.accessToken,
        ctx.config.dwd_service_account,
        email,
      );
    }
  }

  const lifetime = Math.min(token.expiresIn, 3_300) * 1_000;
  await ctx.storage.put(cacheKey, {
    accessToken: token.accessToken,
    expiresAt: Date.now() + lifetime,
  } satisfies TokenCache);
  return token.accessToken;
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

function attachmentParts(
  part: GmailPart | undefined,
  path = "root",
): ConnectorAttachment[] {
  if (!part) return [];
  const own =
    part.filename && (part.body?.attachmentId || part.body?.data)
      ? [{
          id: path,
          name: part.filename,
          ...(part.mimeType ? { contentType: part.mimeType } : {}),
          ...(part.body?.size !== undefined ? { size: part.body.size } : {}),
        }]
      : [];
  return [
    ...own,
    ...(part.parts ?? []).flatMap((child, index) =>
      attachmentParts(child, path === "root" ? String(index) : `${path}.${index}`),
    ),
  ];
}

function partAtPath(
  part: GmailPart | undefined,
  path: string,
): GmailPart | undefined {
  if (!part) return undefined;
  if (path === "root") return part;
  let current: GmailPart | undefined = part;
  for (const raw of path.split(".")) {
    if (!/^(0|[1-9]\d*)$/u.test(raw)) return undefined;
    current = current.parts?.[Number(raw)];
    if (!current) return undefined;
  }
  return current;
}

function decodeBase64UrlBytes(value: string): Uint8Array {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
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
  const attachments = attachmentParts(message.payload).slice(0, 16);
  const text = textBody(message.payload).trim() || message.snippet || "(empty email)";
  const body = `${text}${
    attachments.length > 0
      ? `\n\n[Gmail attachments: ${attachments.length}]`
      : ""
  }`;
  const fromEmail = from.match(/<([^>]+)>/u)?.[1] ?? from;
  return {
    eventKey: `${ctx.config.email}:${message.id}`,
    conversationId: message.threadId,
    user: from,
    trigger: "email",
    content: `New email from ${from}\nSubject: ${subject}\n\n${body}`,
    ...(attachments.length > 0 ? { attachments } : {}),
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

async function fetchAttachment(
  ctx: ConnectorCtx,
  event: ConnectorEvent,
  attachment: ConnectorAttachment,
): Promise<Response> {
  const messageID = event.meta?.gmail_id;
  if (!messageID) throw new Error("Gmail event has no message id");
  const message = await fetchMessage(ctx, messageID);
  const part = partAtPath(message.payload, attachment.id);
  if (!part || part.filename !== attachment.name) {
    throw new Error(`Gmail attachment ${attachment.id} is no longer present`);
  }

  let bytes: Uint8Array;
  if (part.body?.data) {
    bytes = decodeBase64UrlBytes(part.body.data);
  } else if (part.body?.attachmentId) {
    const response = await gmailFetch(
      ctx,
      `/messages/${encodeURIComponent(messageID)}/attachments/${encodeURIComponent(
        part.body.attachmentId,
      )}`,
    );
    const body = (await response.json()) as { data?: string };
    if (!response.ok || !body.data) {
      throw new Error(`Gmail attachment get failed (${response.status})`);
    }
    bytes = decodeBase64UrlBytes(body.data);
  } else {
    throw new Error(`Gmail attachment ${attachment.id} has no data`);
  }

  return new Response(bytes, {
    headers: {
      "content-type": part.mimeType || "application/octet-stream",
      "content-length": String(bytes.byteLength),
    },
  });
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
    { key: "sa_key", label: "Service-account JSON key", secret: true },
    { key: "client_id", label: "OAuth client ID" },
    { key: "client_secret", label: "OAuth client secret", secret: true },
    { key: "refresh_token", label: "OAuth refresh token", secret: true },
    {
      key: "dwd_service_account",
      label: "Keyless DWD service-account email",
      help:
        "Optional. Uses the OAuth refresh token only to call IAM signJwt, then exchanges a domain-wide delegated assertion as the mailbox user.",
    },
    { key: "labels_require", label: "Required labels" },
    { key: "labels_exclude", label: "Excluded labels" },
    { key: "poll_seconds", label: "Poll seconds", placeholder: "60" },
    { key: "instructions", label: "Agent instructions" },
  ],
  start: wake,
  wake,
  fetchAttachment,
  postReply,
} satisfies Connector;

export { normalizeMessage as normalizeGmailMessage };
export default gmail;
