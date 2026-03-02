FROM python:3.12-slim AS runtime

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1

# Install minimal OS packages needed for common Python wheels (Pillow, ReportLab)
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	   libjpeg62-turbo \
	   libfreetype6 \
	   ca-certificates \
	   curl \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
	&& pip install --no-cache-dir -r requirements.txt \
	&& pip install --no-cache-dir gunicorn

# Copy application source
COPY app/ /app/

# Create non-root user and set ownership
RUN useradd -m -u 1001 appuser \
	&& chown -R appuser:appuser /app

USER appuser

# Default Flask/Gunicorn port
EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
	CMD curl -f http://localhost:8000/ || exit 1

# Environment hooks (override at runtime as needed)
# - SECRET_KEY: Flask session secret
# - DB_ENCRYPTION_KEY: key material for field-level encryption
# - POSTGRES_HOST: PostgreSQL hostname (default: localhost)
# - POSTGRES_PORT: PostgreSQL port (default: 5432)
# - POSTGRES_DB: PostgreSQL database name (default: tx_review)
# - POSTGRES_USER: PostgreSQL username (default: tx_user)
# - POSTGRES_PASSWORD: PostgreSQL password (default: tx_password)
ENV FLASK_DEBUG=0

# Start with Gunicorn (app.py exposes `app`)
CMD ["gunicorn", "-w", "8", "-k", "gthread", "--threads", "16", "--max-requests", "1000", "--max-requests-jitter", "50", "--timeout", "120", "-b", "0.0.0.0:8000", "app:app"]

