# Feishu OAuth Service

Lightweight Feishu OAuth callback service. It redirects users to Feishu, exchanges the code for tokens, fetches user info, persists the result, and posts it to a webhook (e.g., n8n).

## Environment

- `FEISHU_APP_ID` (required)
- `FEISHU_APP_SECRET` (required)
- `FEISHU_REDIRECT_URI` (required, e.g. `https://your-domain.com/oauth/callback`)
- `WEBHOOK_URL` (optional, n8n webhook URL)
- `FEISHU_SCOPE` (optional, default `offline_access`)
- `STATE_SECRET` (optional, used to sign the OAuth state)
- `STATE_TTL_SECONDS` (optional, default `600`)
- `STORAGE_PATH` (optional, default `./data/oauth_tokens.json`)
- `HOST` (optional, default `0.0.0.0`)
- `PORT` (optional, default `8000`)
- `CONFIG_PATH` (optional, default `./config.yaml`)

If both config file and env vars are present, env vars take precedence.

## Run locally

```bash
cp config.yaml.example config.yaml

python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export FEISHU_APP_ID=your_app_id
export FEISHU_APP_SECRET=your_app_secret
export FEISHU_REDIRECT_URI=http://localhost:8000/oauth/callback
export WEBHOOK_URL=https://your-n8n-webhook
export FEISHU_SCOPE=offline_access

python app.py
```

Visit `http://localhost:8000/oauth/login`.

## Docker

```bash
docker build -t feishu-oauth .
docker run --rm -p 8000:8000 \
  -e FEISHU_APP_ID=your_app_id \
  -e FEISHU_APP_SECRET=your_app_secret \
  -e FEISHU_REDIRECT_URI=http://localhost:8000/oauth/callback \
  -e WEBHOOK_URL=https://your-n8n-webhook \
  -v "$(pwd)/data:/app/data" \
  feishu-oauth
```

## Endpoints

- `GET /oauth/login` Redirects to Feishu OAuth
- `GET /oauth/callback` Handles the OAuth callback
- `GET /healthz` Health check
