# Getting Started

This guide walks through running the ICS Combiner service locally and with Docker.

## Run Locally

1. Create and populate your environment file:

   ```bash
   cp .env.example .env.local
   # edit .env.local with your ICS sources, Redis, and auth settings
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Start the FastAPI app with Uvicorn:

   ```bash
   python -m uvicorn src.server:app --host 0.0.0.0 --port 8080
   ```

4. Check the health endpoint:

   ```bash
   curl http://localhost:8080/app/health
   ```

## Run with Docker

1. Build the image:

   ```bash
   docker build -t ics-combiner .
   ```

2. Run the container:

   ```bash
   docker run --env-file .env.local -p 8080:8080 ics-combiner
   ```

3. Access endpoints via `http://localhost:8080`.

