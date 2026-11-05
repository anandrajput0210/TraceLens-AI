# Deployment and environment configuration

TraceLens AI can run locally with the default settings below. These settings are intended for development and a single-process demo, not a hardened multi-user production deployment.

## Frontend API URL

Create `frontend/.env.local` from `frontend/.env.example`:

```dotenv
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000
```

`NEXT_PUBLIC_API_BASE_URL` is embedded into the frontend bundle at build time. Set it to the deployed backend's HTTPS base URL before running `npm run build` for a hosted frontend.

## Backend browser origins

By default, the backend allows only `http://localhost:3000` and `http://127.0.0.1:3000`. To allow a hosted frontend, set `TRACELENS_ALLOWED_ORIGINS` on the backend to a comma-separated list of exact origins, for example:

```text
TRACELENS_ALLOWED_ORIGINS=https://your-frontend.example.com
```

Do not set the value to `*`. The backend enables credentialed CORS requests and intentionally rejects wildcard origins. Include the scheme and host (and port when applicable), but no path.

## AI configuration

Set `OPENAI_API_KEY` on the backend only. Optionally set `TRACELENS_AI_MODEL` to a model supported by the API account. Never place secret keys in `NEXT_PUBLIC_*` frontend variables.

## Current MVP limitations

- Analysis results are held in process memory. Restarting the backend loses them, and separate workers do not share analysis state.
- Background analysis jobs are not persisted or restart-safe.
- Static import relationships are heuristic evidence and do not prove runtime execution, data-flow reachability, internet exposure, or exploitability.
- Configure an upstream proxy/server request-size limit as well as the application's request-body middleware for a public deployment.
- Before exposing this service to untrusted users, add authentication/authorization, rate limits, operational monitoring, and a durable job/result store.
