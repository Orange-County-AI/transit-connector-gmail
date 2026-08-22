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
});
