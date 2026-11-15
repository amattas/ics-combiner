<p align="center">
  <img src="docs/logo.svg" width="120" alt="ICS Combiner logo">
</p>

# ICS Combiner (FastAPI)

This service combines multiple iCalendar (ICS) feeds into a single calendar, with optional per‑calendar transforms. It runs as a FastAPI app with the same path‑based authentication scheme used by the MCP servers, and caches source ICS files in PostgreSQL (or in memory for local development) with configurable refresh TTLs.

Key features
- FastAPI app with optional dual‑factor path auth using `ICS_API_KEY` and `SALT` (with legacy `MD5_SALT` support)
- PostgreSQL‑backed caching of source ICS feeds, with last‑known‑good fallback
- Per‑calendar refresh TTL with environment overrides
- Optional show/hide filtering via query params
- Dockerfile and example env provided

Environment
- ICS_API_KEY: API key to enable path‑based auth (optional for local/dev)
- SALT: Optional salt used for API path hash (preferred)
- MD5_SALT: Legacy name for `SALT` (still supported)
- DATABASE_URL: PostgreSQL URL for the source cache (e.g. `postgresql://user:pw@host:5432/ics_combiner?sslmode=require`). Unset: no cache
- CACHE_BACKEND: Set to `memory` for a process-local cache (local development); takes precedence over `DATABASE_URL`
- ICS_CACHE_NAMESPACE: Optional cache key namespace. Set this when several apps share one cache database. If omitted, a namespace is derived from `ICS_API_KEY` when available.
- ICS_SOURCES: JSON array of calendar configs (see example)
- ICS_NAME: Combined calendar display name
- ICS_DAYS_HISTORY: Days of history to include (int)
- CACHE_TTL_ICS_SOURCE_DEFAULT: Default TTL (seconds) for source ICS caching
- CACHE_TTL_ICS_SOURCE_LKG: Optional last-known-good fallback TTL (seconds). Leave unset or set to 0 to retain indefinitely.
- CACHE_TTL_ICS_SOURCE_FAILURE_BACKOFF: Backoff TTL (seconds) after a source fetch failure (minimum 1)
- CACHE_TTL_ICS_SOURCE_RATE_LIMIT_BACKOFF: Backoff TTL (seconds) after HTTP 429 without `Retry-After` (default 3600, minimum 1)

Calendar source config
Each object in `ICS_SOURCES` may include the following keys (compatible with calcomb):
- Id (required, int): unique numeric ID per calendar
- Url (required, string): ICS feed URL
- Duration (optional, minutes): override event duration when DTSTART is datetime
- PadStartMinutes (optional, minutes): prepend minutes and extend duration accordingly
- Prefix (optional, string): prefix for SUMMARY
- MakeUnique (optional, bool): force UID uniqueness per calendar
- FilterDuplicates (optional, bool): de‑duplicate events by UID
- RefreshSeconds (optional, int): cache TTL for this calendar’s source ICS
  - Set to 0 to bypass the fresh source cache while still using failure backoff and last-known-good fallback cache when a cache is configured.

Cache behavior
- The PostgreSQL backend connects lazily (startup never waits for the database) and creates a logged `cache_entries` table on first use, so last-known-good feeds survive a database crash or failover. The database user needs `CREATE` on schema `public`. Cache errors never fail a request: the service logs (at most once a minute per operation), fetches upstream directly for 30 seconds, then retries.
- Cache keys are scoped by app namespace so multiple apps can share one cache database without overwriting each other's source cache. Use a stable `ICS_CACHE_NAMESPACE` per app if `ICS_API_KEY` is not set or if several apps intentionally share an API key.
- Successful source fetches store a last-known-good copy indefinitely by default. A positive `CACHE_TTL_ICS_SOURCE_LKG` can cap that retention.
- Removed calendars are not emitted just because their old source data remains in the cache. The app tracks source keys per namespace and prunes cache entries for sources removed from `ICS_SOURCES` on the next combine request.

Endpoints
- GET /app/health — health status (no auth)
- GET /app/{ICS_API_KEY}/{hash}/ics?show=1,2&hide=3 — combined calendar

Run locally
1) Copy `.env.example` to `.env.local` and set values
2) `pip install -e .`
3) `python -m uvicorn src.server:app --host 0.0.0.0 --port 8080`

Running the tests

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The PostgreSQL cache tests run only when `TEST_DATABASE_URL` points at a scratch database
(the tests drop and recreate its `cache_entries` table):

```bash
docker run -d --rm --name pgtest -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:18
TEST_DATABASE_URL=postgresql://postgres:pw@localhost:55432/postgres python -m pytest -q
docker stop pgtest
```

Docker
- Build: `docker build -t ics-combiner .`
- Run: `docker run --env-file .env.local -p 8080:8080 ics-combiner`
