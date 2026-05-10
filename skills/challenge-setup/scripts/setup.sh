#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed. Please install Docker first." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is not available. Please install Docker Compose plugin." >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ENV_FILE}"
    echo "Created .env from .env.example"
  else
    echo "Missing .env and .env.example in challenge root." >&2
    exit 1
  fi
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

if [[ -z "${FLR_CHALLENGE_API_KEY:-}" ]]; then
  echo "FLR_CHALLENGE_API_KEY is missing in .env" >&2
  echo "Add FLR_CHALLENGE_API_KEY to ${ENV_FILE} and rerun." >&2
  exit 1
fi

echo "Using ENV=${ENV:-LOCAL} DEBUG=${DEBUG:-false}"

if [[ $# -gt 0 && "$1" == "--build" ]]; then
  docker compose up -d --build --remove-orphans
else
  docker compose up -d --remove-orphans
fi

echo "Challenge setup complete."
echo "Run healthcheck: ./skills/challenge-setup/scripts/healthcheck.sh"
