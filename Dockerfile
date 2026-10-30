FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install the application and its dependencies (declared in pyproject.toml).
# The app installs as the `src` package with its metadata, so the version comes
# from importlib.metadata; the build context is removed afterwards.
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /build

WORKDIR /app

# Default to uvicorn
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8080", "--loop", "uvloop", "--http", "httptools", "--log-level", "warning"]
