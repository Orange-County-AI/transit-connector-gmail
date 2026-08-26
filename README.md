# Transit Connector: Gmail

Build-time Gmail History API adapter for Transit. Polls from a durable `historyId` watermark, normalizes new messages, and sends RFC 2822 replies in the original thread.

## Configuration

- `email` — Gmail account address.
- `sa_key` — optional service-account JSON key for domain-wide delegation; secret.
- `client_id` / `client_secret` / `refresh_token` — OAuth refresh credentials; the secret fields are write-only.
- `dwd_service_account` — optional keyless domain-wide-delegation service account. When set, the refresh credential calls IAM `signJwt`; its token is never used against Gmail directly.
- `labels_require` / `labels_exclude` — optional comma-separated label filters.
- `poll_seconds` — polling interval; minimum 30, default 60.
- `instructions` — optional text appended to `read_message` results.

Use exactly one authority path: a service-account JSON key; ordinary OAuth refresh credentials for the mailbox; or refresh credentials plus `dwd_service_account` for keyless IAM signing. The first successful start records the current profile `historyId` without replaying old mail. A 404 history expiry resets that watermark and records the possible gap.

Filename, MIME type, size, and MIME-part identity are stored with each event. Attachment bytes stay in Gmail until the assigned agent calls `read_message`; Transit fetches them with the integration's OAuth credential and materializes local files without exposing that credential.

```bash
bun install
bun run typecheck
bun run test
```

MIT licensed.
