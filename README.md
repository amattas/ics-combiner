ICS Combiner (FastAPI)

This service combines multiple iCalendar (ICS) feeds into a single calendar, with optional per‑calendar transforms. It runs as a FastAPI app with the same path‑based authentication scheme used by the MCP servers, and supports Redis caching for source ICS files with configurable refresh TTLs.

Key features
- FastAPI app with optional dual‑factor path auth using `ICS_API_KEY` and `SALT` (with legacy `MD5_SALT` support)
- Redis‑backed caching of source ICS feeds
- Per‑calendar refresh TTL with environment overrides
- Optional show/hide filtering via query params
- Dockerfile and example env provided

Environment
- ICS_API_KEY: API key to enable path‑based auth (optional for local/dev)
- SALT: Optional salt used for API path hash (preferred)
- MD5_SALT: Legacy name for `SALT` (still supported)
- REDIS_HOST, REDIS_SSL_PORT (default 6380), REDIS_KEY: Redis connection
- ICS_SOURCES: JSON array of calendar configs (see example)
- ICS_NAME: Combined calendar display name
- ICS_DAYS_HISTORY: Days of history to include (int)
- CACHE_TTL_ICS_SOURCE_DEFAULT: Default TTL (seconds) for source ICS caching

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

Endpoints
- GET /app/health — health status (no auth)
- GET /app/{ICS_API_KEY}/{hash}/ics?show=1,2&hide=3 — combined calendar

Run locally
1) Copy `.env.example` to `.env.local` and set values
2) `pip install -r requirements.txt`
3) `python -m uvicorn src.server:app --host 0.0.0.0 --port 8080`

Docker
- Build: `docker build -t ics-combiner .`
- Run: `docker run --env-file .env.local -p 8080:8080 ics-combiner`
