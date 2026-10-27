
# ARGUS-X

Modular cybersecurity platform.

## Layer 1: Traffic Guard

Provides application-level per-client rate limiting.

### Local setup

1. Create a virtual environment.
2. Install dependencies.
3. Configure `.env`.
4. Start the API.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Health endpoint: `http://127.0.0.1:8001/health`

### Tests

```powershell
python -m pytest -q
```

### Production requirements

- Configure Redis as the shared rate-limit backend.
- Set `APP_ENV=production`.
- Set `RATE_LIMIT_BACKEND=redis`.
- Provide `REDIS_URL` through the deployment secret manager.
- Configure trusted proxy handling before deployment behind a reverse proxy.
- Validate rate limits, load, false positives and failure behavior.

The in-memory backend is for local development and tests only.
This layer does not provide volumetric network-level DDoS protection.
