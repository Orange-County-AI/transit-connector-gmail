import { describe, expect, it } from "vitest";
import type { ConnectorCtx } from "transit-connector-kit";
import { normalizeGmailMessage } from "../src";

function context(config: Record<string, string>): ConnectorCtx {
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
    fetch,
    scheduleWake: () => undefined,
    settleConversation: async () => undefined,
    setStatus: () => undefined,
    log: () => undefined,
    openWebSocket: async () => {
      throw new Error("not used");
    },
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
});
