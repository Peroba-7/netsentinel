#!/usr/bin/env bash
# Instala no n8n do Docker Compose o workflow de bloqueio e o segredo do webhook.
# O segredo vem de N8N_WEBHOOK_SECRET no .env e nunca é gravado no repositório.
# Uso (na raiz do projeto): ./n8n/install-workflow.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="netsentinel-n8n"

secret="$(grep -E '^N8N_WEBHOOK_SECRET=.+' "$root/.env" | head -n1 | cut -d= -f2- | tr -d '\r' || true)"
[ -n "$secret" ] || { echo "Defina N8N_WEBHOOK_SECRET no .env antes de instalar o workflow." >&2; exit 1; }
[ "${#secret}" -ge 16 ] || { echo "N8N_WEBHOOK_SECRET deve ter pelo menos 16 caracteres." >&2; exit 1; }
case "$secret" in *[!A-Za-z0-9_-]*) echo "Use só letras, números, - e _ no segredo." >&2; exit 1 ;; esac

tmp="$(mktemp)"
# O docker cp cria os ficheiros como root; o n8n corre como node e não os pode apagar.
trap 'rm -f "$tmp"; docker exec -u root "$container" rm -f /tmp/cred.json /tmp/wf.json 2>/dev/null || true' EXIT
printf '[{"id":"netsentinelWebhookAuth","name":"NetSentinel webhook","type":"httpHeaderAuth","data":{"name":"X-NetSentinel-Secret","value":"%s"}}]' "$secret" > "$tmp"

docker cp "$tmp" "$container:/tmp/cred.json"
docker exec "$container" n8n import:credentials --input=/tmp/cred.json
docker cp "$root/n8n/netsentinel-block-simulation.json" "$container:/tmp/wf.json"
docker exec "$container" n8n import:workflow --input=/tmp/wf.json
docker exec "$container" n8n publish:workflow --id=netsentinelBlockSim
docker compose -f "$root/docker-compose.yml" restart n8n
echo "Workflow instalado. O webhook agora exige o cabeçalho X-NetSentinel-Secret."
