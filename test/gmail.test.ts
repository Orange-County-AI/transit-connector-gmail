import { describe, expect, it } from "vitest";
import type { ConnectorCtx } from "transit-connector-kit";
import gmail, { normalizeGmailMessage } from "../src";

function context(config: Record<string, string>, connectorFetch: typeof fetch = fetch): ConnectorCtx {
  const durable = new Map<string, unknown>();
  const runtime = new Map<string, unknown>();
  return {
    config,
    storage: {
      get: async <T>(key: string) => durable.get(key) as T | undefined,
      put: async (key, value) => {
        durable.set(key, value);
      },
      delete: async (key) => {
        durable.delete(key);
      },
      list: async <T>(prefix: string) =>
        new Map(
          [...durable]
            .filter(([key]) => key.startsWith(prefix))
            .map(([key, value]) => [key, value as T]),
        ),
    },
    runtime: {
      get: <T>(key: string) => runtime.get(key) as T | undefined,
      set: (key, value) => {
        runtime.set(key, value);
      },
      delete: (key) => {
        runtime.delete(key);
      },
    },
    ingest: async () => ({ status: "queued" }),
    fetch: connectorFetch,
    scheduleWake: () => undefined,
    settleConversation: async () => undefined,
    setStatus: () => undefined,
    log: () => undefined,
    openWebSocket: async () => {
      throw new Error("not used");
    },
  };
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value
    .replaceAll("-", "+")
    .replaceAll("_", "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function decodeJwtPart(value: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value))) as Record<string, unknown>;
}

async function throwawayServiceAccount(): Promise<{
  json: string;
  publicKey: CryptoKey;
}> {
  const keys = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2_048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  if (!(exported instanceof ArrayBuffer)) throw new Error("failed to export throwaway key");
  const pkcs8 = new Uint8Array(exported);
  let binary = "";
  for (const byte of pkcs8) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).match(/.{1,64}/gu)?.join("\n");
  if (!encoded) throw new Error("failed to encode throwaway key");
  return {
    json: JSON.stringify({
      client_email: "gmail-test@project.iam.gserviceaccount.com",
      private_key: `-----BEGIN PRIVATE KEY-----\n${encoded}\n-----END PRIVATE KEY-----\n`,
    }),
    publicKey: keys.publicKey,
  };
}

describe("Gmail connector", () => {
  it("normalizes headers, thread identity, and text body", async () => {
    const event = await normalizeGmailMessage(
      context({ email: "agent@example.com", labels_require: "INBOX" }),
      {
        id: "gmail-1",
        threadId: "thread-1",
        labelIds: ["INBOX"],
        payload: {
          mimeType: "text/plain",
          headers: [
            { name: "From", value: "Ada <ada@example.com>" },
            { name: "Subject", value: "Transit status" },
            { name: "Message-ID", value: "<message-1@example.com>" },
          ],
          body: { data: "aGVsbG8gdHJhbnNpdA" },
        },
      },
    );
    expect(event).toMatchObject({
      eventKey: "agent@example.com:gmail-1",
      conversationId: "thread-1",
      user: "Ada <ada@example.com>",
      content:
        "New email from Ada <ada@example.com>\nSubject: Transit status\n\nhello transit",
      meta: {
        from_email: "ada@example.com",
        thread_id: "thread-1",
      },
    });
  });

  it("declares nested files and streams Gmail attachment bytes", async () => {
    const message = {
      id: "gmail-file",
      threadId: "thread-file",
      labelIds: ["INBOX"],
      payload: {
        mimeType: "multipart/mixed",
        headers: [
          { name: "From", value: "Ada <ada@example.com>" },
          { name: "Subject", value: "The brief" },
        ],
        parts: [
          {
            mimeType: "text/plain",
            body: { data: "cGxlYXNlIHJldmlldw" },
          },
          {
            mimeType: "application/pdf",
            filename: "brief.pdf",
            body: { attachmentId: "attachment-1", size: 3 },
          },
        ],
      },
    };
    const connectorFetch = (async (input: RequestInfo | URL) => {
      const url = new URL(input.toString());
      if (url.origin === "https://oauth2.googleapis.com") {
        return Response.json({ access_token: "access", expires_in: 3_600 });
      }
      if (url.pathname.endsWith("/messages/gmail-file")) {
        return Response.json(message);
      }
      if (url.pathname.endsWith("/attachments/attachment-1")) {
        return Response.json({ data: "AQID", size: 3 });
      }
      throw new Error(`unexpected Gmail call: ${url}`);
    }) as typeof fetch;
    const ctx = context(
      {
        email: "agent@example.com",
        client_id: "client",
        client_secret: "secret",
        refresh_token: "refresh",
      },
      connectorFetch,
    );
    const event = await normalizeGmailMessage(ctx, message);
    expect(event?.attachments).toEqual([
      {
        id: "1",
        name: "brief.pdf",
        contentType: "application/pdf",
        size: 3,
      },
    ]);
    expect(event?.content).toContain("[Gmail attachments: 1]");

    const response = await gmail.fetchAttachment!(
      ctx,
      event!,
      event!.attachments![0]!,
    );
    expect(response.headers.get("content-type")).toBe("application/pdf");
    expect([...new Uint8Array(await response.arrayBuffer())]).toEqual([1, 2, 3]);
  });

  it("filters required and excluded labels", async () => {
    const event = await normalizeGmailMessage(
      context({
        email: "agent@example.com",
        labels_require: "INBOX",
        labels_exclude: "SPAM",
      }),
      {
        id: "gmail-2",
        threadId: "thread-2",
        labelIds: ["INBOX", "SPAM"],
      },
    );
    expect(event).toBeNull();
  });
  it("uses a signed, cached domain-wide delegation token", async () => {
    const serviceAccount = await throwawayServiceAccount();
    const assertions: string[] = [];
    let tokenRequests = 0;
    const connectorFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.hostname === "oauth2.googleapis.com") {
        tokenRequests += 1;
        const form = new URLSearchParams(await request.text());
        const assertion = form.get("assertion");
        if (!assertion) throw new Error("missing service-account assertion");
        assertions.push(assertion);
        expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
        return Response.json({ access_token: "service-account-token", expires_in: 3_600 });
      }
      if (url.hostname === "gmail.googleapis.com") {
        return Response.json({ historyId: "history-1" });
      }
      throw new Error(`unexpected fetch: ${request.url}`);
    };
    const ctx = context(
      { email: "clem@orangecountyai.com", sa_key: serviceAccount.json },
      connectorFetch,
    );

    await gmail.start(ctx);
    await gmail.wake(ctx);

    expect(tokenRequests).toBe(1);
    const assertion = assertions[0];
    if (!assertion) throw new Error("no service-account assertion recorded");
    const [encodedHeader, encodedPayload, encodedSignature] = assertion.split(".");
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
      throw new Error("JWT assertion had an invalid shape");
    }
    expect(decodeJwtPart(encodedHeader)).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = decodeJwtPart(encodedPayload);
    expect(claims).toMatchObject({
      iss: "gmail-test@project.iam.gserviceaccount.com",
      sub: "clem@orangecountyai.com",
      aud: "https://oauth2.googleapis.com/token",
      scope: "https://mail.google.com/",
    });
    expect((claims.exp as number) - (claims.iat as number)).toBe(3_600);
    await expect(
      crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        serviceAccount.publicKey,
        base64UrlToBytes(encodedSignature),
        new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
      ),
    ).resolves.toBe(true);
  });

  it("fails loudly instead of falling back when the service-account key is malformed", async () => {
    const connectorFetch: typeof fetch = async () => {
      throw new Error("OAuth must not be attempted");
    };
    await expect(
      gmail.start(
        context(
          {
            email: "clem@orangecountyai.com",
            sa_key: "{broken JSON",
            client_id: "legacy-client",
            client_secret: "legacy-secret",
            refresh_token: "legacy-refresh-token",
          },
          connectorFetch,
        ),
      ),
    ).rejects.toThrow("Gmail service-account key is invalid: not valid JSON");
  });

  it("uses refresh credentials only to sign a keyless DWD assertion", async () => {
    const forms: URLSearchParams[] = [];
    let signedPayload: Record<string, unknown> | undefined;
    const connectorFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.hostname === "oauth2.googleapis.com") {
        const form = new URLSearchParams(await request.text());
        forms.push(form);
        if (form.get("grant_type") === "refresh_token") {
          return Response.json({ access_token: "caller-token", expires_in: 3_600 });
        }
        expect(form.get("assertion")).toBe("signed-jwt");
        return Response.json({ access_token: "delegated-token", expires_in: 3_600 });
      }
      if (url.hostname === "iamcredentials.googleapis.com") {
        expect(request.headers.get("authorization")).toBe("Bearer caller-token");
        expect(url.pathname).toContain(
          "workspace-admin%40ticket-500-501723.iam.gserviceaccount.com",
        );
        const body = (await request.json()) as { payload: string };
        signedPayload = JSON.parse(body.payload) as Record<string, unknown>;
        return Response.json({ signedJwt: "signed-jwt" });
      }
      if (url.hostname === "gmail.googleapis.com") {
        expect(request.headers.get("authorization")).toBe("Bearer delegated-token");
        return Response.json({ historyId: "history-1" });
      }
      throw new Error(`unexpected fetch: ${request.url}`);
    };

    const ctx = context(
      {
        email: "stub@theticket500.com",
        client_id: "caller-client",
        client_secret: "caller-secret",
        refresh_token: "caller-refresh",
        dwd_service_account:
          "workspace-admin@ticket-500-501723.iam.gserviceaccount.com",
      },
      connectorFetch,
    );
    await ctx.storage.put("token:stub@theticket500.com:oauth", {
      accessToken: "stale-caller-token",
      expiresAt: Date.now() + 3_600_000,
    });
    await gmail.start(ctx);

    expect(forms).toHaveLength(2);
    expect(signedPayload).toMatchObject({
      iss: "workspace-admin@ticket-500-501723.iam.gserviceaccount.com",
      sub: "stub@theticket500.com",
      aud: "https://oauth2.googleapis.com/token",
      scope: "https://mail.google.com/",
    });
  });

  it("continues to exchange a configured refresh token", async () => {
    let tokenRequest: URLSearchParams | undefined;
    const connectorFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.hostname === "oauth2.googleapis.com") {
        tokenRequest = new URLSearchParams(await request.text());
        return Response.json({ access_token: "refresh-token-access", expires_in: 3_600 });
      }
      if (url.hostname === "gmail.googleapis.com") {
        expect(request.headers.get("authorization")).toBe("Bearer refresh-token-access");
        return Response.json({ historyId: "history-1" });
      }
      throw new Error(`unexpected fetch: ${request.url}`);
    };

    await gmail.start(
      context(
        {
          email: "clem@orangecountyai.com",
          client_id: "legacy-client",
          client_secret: "legacy-secret",
          refresh_token: "legacy-refresh-token",
        },
        connectorFetch,
      ),
    );

    expect(tokenRequest).toBeDefined();
    expect(Object.fromEntries(tokenRequest ?? [])).toEqual({
      client_id: "legacy-client",
      client_secret: "legacy-secret",
      refresh_token: "legacy-refresh-token",
      grant_type: "refresh_token",
    });
  });

  it("skips a hard-deleted message and still advances the watermark", async () => {
    // The regression this exists for: a 404 on ONE message used to throw out of
    // the history loop before `history_id` was committed, so every later poll
    // re-read the same page, re-fetched the same dead id and threw again. The
    // assertion that matters is the watermark MOVING -- without it the mailbox
    // is blocked forever, which is what happened to ws-ticket500 for 5h45m.
    const ingested: string[] = [];
    const connectorFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.hostname === "oauth2.googleapis.com") {
        return Response.json({ access_token: "token", expires_in: 3_600 });
      }
      if (url.pathname.endsWith("/history")) {
        return Response.json({
          history: [
            {
              id: "20500",
              messagesAdded: [
                { message: { id: "dead-message" } },
                { message: { id: "live-message" } },
              ],
            },
          ],
          historyId: "20530",
        });
      }
      if (url.pathname.endsWith("/messages/dead-message")) {
        return Response.json({ error: { message: "Not Found" } }, { status: 404 });
      }
      if (url.pathname.endsWith("/messages/live-message")) {
        return Response.json({
          id: "live-message",
          threadId: "live-thread",
          labelIds: ["INBOX"],
          snippet: "still here",
          payload: { headers: [{ name: "From", value: "stacey@theticket500.com" }] },
        });
      }
      throw new Error(`unexpected fetch: ${request.url}`);
    };

    const ctx = context(
      { email: "stub@theticket500.com", refresh_token: "r", client_id: "c", client_secret: "s" },
      connectorFetch,
    );
    ctx.ingest = async (event) => {
      ingested.push(String(event.meta?.gmail_id));
      return { status: "queued" };
    };
    await ctx.storage.put("history_id", "20419");

    await gmail.wake(ctx);

    // The dead id is skipped, the live one behind it is NOT lost, and the
    // watermark leaves 20419 -- the three properties the poison pill broke.
    expect(ingested).toEqual(["live-message"]);
    expect(await ctx.storage.get("history_id")).toBe("20530");
  });
});
