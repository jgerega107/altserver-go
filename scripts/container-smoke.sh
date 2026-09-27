#!/usr/bin/env bash
set -euo pipefail
image="${1:-altserver:local}"
name="altserver-smoke-${RANDOM}"
state="${name}-state"
work="${name}-work"
secret="$(mktemp)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$state" "$work" >/dev/null 2>&1 || true
  rm -f "$secret"
}
trap cleanup EXIT
printf 'container-smoke-only-password-%s\n' "$RANDOM" > "$secret"
# Bind-mounted secrets must be readable by the container UID; the parent
# temporary path is used only for this non-sensitive smoke-test credential.
chmod 644 "$secret"
test "$(docker image inspect -f '{{.Config.User}}' "$image")" = '10001:10001'
docker run -d --name "$name" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,nosuid,noexec,size=32m \
  -v "$state:/var/lib/altserver" -v "$work:/var/cache/altserver" \
  -v "$secret:/run/secrets/admin_password:ro" \
  -e ALTSERVER_ADMIN_PASSWORD_FILE=/run/secrets/admin_password \
  -e ALTSERVER_DISCOVERY=false "$image" >/dev/null
for attempt in $(seq 1 30); do
  if docker exec "$name" altserver healthcheck; then break; fi
  sleep 1
done
docker exec "$name" altserver healthcheck
docker exec "$name" sh -c 'test "$(id -u)" = 10001; test ! -w /usr/local/bin; test -w /var/lib/altserver; zsign --version'
before="$(docker exec "$name" cat /var/lib/altserver/identity.json)"
docker restart --time 75 "$name" >/dev/null
for attempt in $(seq 1 30); do
  if docker exec "$name" altserver healthcheck; then break; fi
  sleep 1
done
docker exec "$name" altserver healthcheck
after="$(docker exec "$name" cat /var/lib/altserver/identity.json)"
test "$before" = "$after"
docker stop --time 75 "$name" >/dev/null
test "$(docker inspect -f '{{.State.ExitCode}}' "$name")" = 0
echo 'Container smoke test passed.'
