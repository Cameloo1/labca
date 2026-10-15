#!/bin/sh
set -eu

usage() {
  echo "usage: docker-entrypoint.sh serve | migrate | cli <args...>" >&2
  exit 2
}

if [ "$#" -lt 1 ]; then
  usage
fi

case "$1" in
  serve)
    # uvicorn 0.54.0 accepts a comma-separated list of IPs and CIDR networks
    # (for example "10.42.0.0/16"). The workload rate limiter and the CRL lock
    # are in-process, so exactly one worker is required.
    if [ "${FORWARDED_ALLOW_IPS:-}" = "*" ]; then
      echo "error: FORWARDED_ALLOW_IPS=* is not allowed" >&2
      exit 2
    fi
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 1 \
      --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
      --no-server-header --log-level "${UVICORN_LOG_LEVEL:-info}"
    ;;
  migrate)
    exec python -m alembic -c /app/alembic.ini upgrade head
    ;;
  cli)
    shift
    exec python -m app.cli "$@"
    ;;
  *)
    usage
    ;;
esac
