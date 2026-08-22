# Transit Connector: Gmail

Build-time Gmail History API adapter for Transit. Polls from a durable `historyId` watermark, normalizes new messages, and sends RFC 2822 replies in the original thread.

## Configuration

- `email` — Gmail account address.
- `client_id` — dedicated OAuth client ID.
- `client_secret` — OAuth client secret; secret.
- `refresh_token` — offline refresh token for the account; secret.
- `labels_require` / `labels_exclude` — optional comma-separated label filters.
- `poll_seconds` — polling interval; minimum 30, default 60.
- `instructions` — optional text appended to `read_message` results.

Create a Google OAuth client, complete one local consent flow with offline access, and store the refresh token in the Transit integration form. The first successful start records the current profile `historyId` without replaying old mail. A 404 history expiry resets that watermark and records the possible gap.

```bash
bun install
bun run typecheck
bun run test
```

MIT licensed.
