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
    Set to `0` to bypass the fresh source cache while still using failure backoff and last-known-good fallback cache when Redis is configured.

- `ICS_NAME` – Combined calendar display name
- `ICS_DAYS_HISTORY` – Days of history to include (int)

## Redis Cache

For Redis‑backed caching of source ICS feeds:

- `REDIS_HOST` – Redis hostname
- `REDIS_SSL_PORT` – Redis SSL port (default: `6380`)
- `REDIS_KEY` – Redis access key

- `CACHE_TTL_ICS_SOURCE_DEFAULT` – Default TTL (seconds) for source ICS caching (used when a source does not define `RefreshSeconds`)
- `CACHE_TTL_ICS_SOURCE_LKG` – Last-known-good fallback TTL (seconds; default: `86400`; minimum: `1`)
- `CACHE_TTL_ICS_SOURCE_FAILURE_BACKOFF` – Backoff TTL after a source fetch failure (seconds; default: `60`; minimum: `1`)

When configured, ICS Combiner will use Redis to cache fetched ICS files to reduce load on upstream calendar providers.
