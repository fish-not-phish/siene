#!/bin/sh
set -e

# Only the gunicorn (web) process owns migrations and static files.
# Workers and beat skip these steps — they share the same image but don't
# need to run management commands on every restart.
if [ "$1" = "gunicorn" ] || [ -z "$1" ]; then
  echo "==> Generating registry keys (idempotent)..."
  python manage.py generate_registry_keys

  echo "==> Running database migrations..."
  python manage.py migrate --noinput

  echo "==> Collecting static files..."
  python manage.py collectstatic --noinput --clear

  echo "==> Starting Gunicorn..."
  exec gunicorn backend.wsgi:application \
      --bind 0.0.0.0:8000 \
      --workers "${GUNICORN_WORKERS:-4}" \
      --worker-class "${GUNICORN_WORKER_CLASS:-sync}" \
      --timeout "${GUNICORN_TIMEOUT:-120}" \
      --forwarded-allow-ips "*" \
      --access-logfile - \
      --error-logfile -
else
  echo "==> Running: $*"
  exec "$@"
fi
