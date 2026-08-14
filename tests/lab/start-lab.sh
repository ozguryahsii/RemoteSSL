#!/usr/bin/env bash
# Starts the integration lab target of design doc §36.2 and prints the environment the tests read.
#
#   eval "$(tests/lab/start-lab.sh)" && dotnet test
#
# Without this, the lab tests skip themselves, so a normal build stays hermetic.
set -euo pipefail

NAME="${REMOTESSL_LAB_NAME:-lab-ssh}"
PORT="${REMOTESSL_LAB_PORT:-2222}"
USER_NAME="${REMOTESSL_LAB_USER:-remotessl}"
PASSWORD="${REMOTESSL_LAB_PASSWORD:-labpassword}"

if ! docker inspect "$NAME" >/dev/null 2>&1; then
    docker run -d --name "$NAME" -p "${PORT}:2222" \
        -e PUID=1000 -e PGID=1000 \
        -e PASSWORD_ACCESS=true \
        -e USER_NAME="$USER_NAME" \
        -e USER_PASSWORD="$PASSWORD" \
        linuxserver/openssh-server:latest >/dev/null
fi

# Wait for sshd rather than guessing; a lab that is not ready yet fails tests for the wrong reason.
for _ in $(seq 1 30); do
    if docker exec "$NAME" sh -c 'nc -z 127.0.0.1 2222' >/dev/null 2>&1; then break; fi
    sleep 1
done

echo "export REMOTESSL_LAB_SSH=127.0.0.1:${PORT}"
echo "export REMOTESSL_LAB_USER=${USER_NAME}"
echo "export REMOTESSL_LAB_PASSWORD=${PASSWORD}"
