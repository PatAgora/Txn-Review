# Copilot Instructions for Scrutinise Webapp

Purpose: Make AI coding agents immediately productive in this Flask/PostgreSQL codebase. Keep edits aligned with the ongoing migration from a monolith (`app/app.py`) to a modular blueprint/route architecture.

Big picture architecture
- Flask app with two entry styles: legacy monolith `app/app.py` and modern factory `app/app_factory.py` + `wsgi.py`. Prefer the factory and blueprints; do not add new routes to `app.py` unless explicitly migrating.
- Modular HTTP surface:
  - Business domains in `app/blueprints/` (`auth`, `admin`, `qc`, `reviewer`, `reporting`) with URL prefixes (`/auth`, `/admin`, `/qc`, ...).
  - Cross-cutting technical routes in `app/routes/` (`core`, `task_management`, `sme`, `api`). Use these when logic spans domains (health, exports, workflows).
- Database: PostgreSQL only via `app/database.py`. A thin compatibility layer converts SQLite-style `?` placeholders to Postgres `%s`. Always use parameterized queries.
- Templates/Javascript: Jinja2 in `app/templates/`; static assets in `app/static/`. Use `url_for('<blueprint>.<endpoint>')` in templates consistent with blueprint names.

Critical development workflows
- Run via Docker (recommended):
  - `docker compose up -d` then `docker compose logs webapp --follow` and open http://localhost:8080. A default admin is created on first run and printed to logs.
  - Tests: `docker compose exec webapp python -m pytest tests/ -v` (coverage: `--cov=. --cov-report=html`).
- Run locally (no Docker):
  - `cd app && python app.py` for dev; `gunicorn wsgi:app` for prod-like.
- Database ops in Docker: `docker compose exec postgres psql -U scrutinise_user -d scrutinise_workflow`. Data persists in a volume; `docker compose down -v` destroys it.

Project-specific conventions and safety
- Security & access control: decorate routes with `utils.role_required(...)`. CSRF is enabled globally; tests disable it via config.
- SQL safety: never interpolate user input into SQL or column names. Use:
  - `utils.validate_level(level)` and `utils.get_safe_column_name(level, column_type)` when building dynamic column references like `l{level}_assigned_to`.
  - Parameterized queries only (use `?` placeholders); the DB layer adapts to `%s` (`DatabaseCursor.execute`).
- Connections: get a connection with `from database import get_db`/`get_db_connection()` and close/commit promptly. Within requests you can reuse the pattern in `app/app.py:get_db_with_cleanup()` that stores `g.db_connection`.
- Logging & audit: initialize via `app/config/logging.py::setup_logging()`. Use loggers `app`, `security`, and `audit` for app, security, and audit trails respectively. Prefer utilities under `app/utils/` (`audit_*`, `security_monitoring.py`, `error_handling.py`).

Where to add or move code
- New business routes: place in the appropriate blueprint file under `app/blueprints/`, keep URL prefixes consistent (e.g., `/admin/users`, `/qc/dashboard`).
- Cross-domain workflows (assign/reassign, exports, health): place in `app/routes/` (`task_management.py`, `api.py`, `core.py`, `sme.py`).
- Configuration: add environment-driven settings in `app/config/config.py`; avoid hardcoding secrets; reference envs already used in `docker-compose.yml`.

Patterns and examples
- Health endpoints live in `app/routes/core.py` (e.g., `/health`).
- Task assignment workflow endpoints live in `app/routes/task_management.py` under `/tasks/*` and enforce roles like `team_lead_1`.
- Authentication/password flows are handled in `app/blueprints/auth.py` (e.g., `/auth/login`, reset password email via SMTP envs).

Testing notes
- Tests use pytest under `tests/`. Prefer containerized execution. Some legacy tests assume SQLite fixtures (`tests/conftest.py`); when updating, align them with the Postgres-first app layer or provide isolated test DB setup.

Key references
- Top-level overview and commands: `README.md` (Quick Start, Docker, Testing, Troubleshooting).
- Migration plan and URL conventions: `app/README.md`, `app/blueprints/README.md`, `app/routes/README.md`.
- DB layer and SQL compatibility: `app/database.py`.
- Security utilities and status derivation: `app/utils.py` and `app/utils/*.py`.

When in doubt
- Favor the blueprint/route modules over adding to `app.py`.
- Reuse helpers: `role_required`, `validate_level`, `get_safe_column_name`, parameterized queries.
- Keep URLs, roles, and templates consistent with the docs linked above.
