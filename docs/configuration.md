# Configuration

ICS Combiner is configured via environment variables. These are typically set in an `.env.local` file for local development or Docker.

## Core Settings

- `ICS_API_KEY` – API key to enable path‑based authentication (optional for local/dev)
- `SALT` – Optional salt used when computing the API path hash (preferred)
- `MD5_SALT` – Legacy name for `SALT` (still supported)

## Calendar Sources

- `ICS_SOURCES` – JSON array of calendar configs. Each object may include:

  - `Id` (required, int): unique numeric ID per calendar
  - `Url` (required, string): ICS feed URL
  - `Duration` (optional, minutes): override event duration when DTSTART is datetime
  - `PadStartMinutes` (optional, minutes): prepend minutes and extend duration accordingly
  - `Prefix` (optional, string): prefix for SUMMARY
  - `MakeUnique` (optional, bool): force UID uniqueness per calendar
  - `FilterDuplicates` (optional, bool): de‑duplicate events by UID
  - `RefreshSeconds` (optional, int): cache TTL for this calendar’s source ICS
    Set to `0` to bypass the fresh source cache while still using failure backoff and last-known-good fallback cache when a cache is configured.

- `ICS_NAME` – Combined calendar display name
- `ICS_DAYS_HISTORY` – Days of history to include (int)

## Cache

The cache is optional. `CACHE_BACKEND=memory` selects a process-local cache; otherwise a set
`DATABASE_URL` selects PostgreSQL; with neither, every request fetches the upstream feeds.

- `DATABASE_URL` – PostgreSQL URL, e.g. `postgresql://user:password@host:5432/ics_combiner?sslmode=require`
- `CACHE_BACKEND` – `memory` for a process-local cache (local development); takes precedence over `DATABASE_URL`
- `ICS_CACHE_NAMESPACE` – Optional cache key namespace. Set this to a stable, unique value per app when several apps share one cache database. If omitted, a namespace is derived from `ICS_API_KEY` when available.

- `CACHE_TTL_ICS_SOURCE_DEFAULT` – Default TTL (seconds) for source ICS caching (used when a source does not define `RefreshSeconds`)
- `CACHE_TTL_ICS_SOURCE_LKG` – Optional last-known-good fallback TTL (seconds). Leave unset or set to `0` to retain indefinitely, which is the default.
- `CACHE_TTL_ICS_SOURCE_FAILURE_BACKOFF` – Backoff TTL after a source fetch failure (seconds; default: `60`; minimum: `1`)
- `CACHE_TTL_ICS_SOURCE_RATE_LIMIT_BACKOFF` – Backoff TTL after HTTP 429 without `Retry-After` (seconds; default: `3600`; minimum: `1`)

When configured, ICS Combiner caches fetched ICS files to reduce load on upstream calendar providers. The PostgreSQL backend:

- connects lazily on first use (startup never waits for the database);
- creates its table, `cache_entries`, on first connect. It is a logged table, so last-known-good feeds and the sources index (stored with no expiry) survive a database crash or failover. The database user needs `CREATE` on schema `public`; if it lacks it, the service logs a warning naming the fix (`GRANT ALL ON SCHEMA public TO <user>`, run as `postgres`);
- never fails a request: after any database error it logs (at most once a minute per operation), fetches upstream directly for 30 seconds, then retries.

Cache keys are scoped by namespace so multiple apps can share the same cache database. The app also tracks source keys in that namespace and deletes cached primary/LKG entries for calendars removed from `ICS_SOURCES` on the next combine request.
