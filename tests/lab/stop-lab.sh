#!/usr/bin/env bash
# Tears the lab target down. Safe to run when nothing is up.
set -euo pipefail
docker rm -f "${REMOTESSL_LAB_NAME:-lab-ssh}" >/dev/null 2>&1 || true
