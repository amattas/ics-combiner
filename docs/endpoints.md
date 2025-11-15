# Endpoints

ICS Combiner exposes a small set of HTTP endpoints for health checks and combined calendar retrieval.

## Health

- `GET /app/health` – Returns basic health status (no authentication required).

## Combined Calendar

- `GET /app/{ICS_API_KEY}/{hash}/ics`

  Returns the combined ICS calendar built from the configured `ICS_SOURCES`.

  Query parameters:

  - `show`: optional comma‑separated list of calendar IDs to include (e.g. `show=1,2`).
  - `hide`: optional comma‑separated list of calendar IDs to exclude (e.g. `hide=3`).

  Authentication:

  - `ICS_API_KEY` is the API key configured via environment variable.
  - `hash` is computed from `ICS_API_KEY` and optional `SALT` (or legacy `MD5_SALT`) using SHA‑256 (same scheme as the MCP servers).
