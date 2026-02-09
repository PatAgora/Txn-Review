# Codex / Agent Instructions (Txn-Review)

## What this repo is
A Flask-based Transaction Review web app (AML/FinCrime use case) using server-rendered Jinja templates + static assets.

## Quick start (local)
Use Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

App runs on `http://localhost:3000`.

## Common commands (for agents)
- Install deps: `pip install -r requirements.txt`
- Run the app: `python app.py`
- Basic smoke check (no tests framework): `python -m compileall .`

## Data / database
- The app initializes its SQLite DB on startup (inside `app.py` main).
- Do **not** commit any generated databases or uploads.

## Repo conventions
- Keep changes minimal and targeted.
- Prefer small, readable helper functions over large inline blocks.
- When changing templates, keep HTML formatting consistent with existing files.
- Never hardcode secrets. If you add config, wire it via environment variables and update `.env.example`.

## Safety / performance
- Avoid loading large binary assets into memory.
- Do not add new heavy dependencies unless necessary.
