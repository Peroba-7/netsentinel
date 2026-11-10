#!/usr/bin/env sh
# Descarrega as bases DB-IP Lite (país e ASN) para data/geoip/.
# Uso: ./scripts/update-geoip.sh
#
# O DB-IP publica uma versão nova no dia 1 de cada mês; se a do mês ainda não existir,
# usa a do mês anterior. Nenhum IP de incidente sai da máquina.
# Licença dos dados: CC BY 4.0, "IP Geolocation by DB-IP" (https://db-ip.com).
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
dir="$root/data/geoip"
mkdir -p "$dir"

current="$(date -u +%Y-%m)"
previous="$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m)"

for name in dbip-country-lite dbip-asn-lite; do
  tmp="$dir/$name.mmdb.tmp"
  downloaded=""
  for month in "$current" "$previous"; do
    if curl -fsSL "https://download.db-ip.com/free/$name-$month.mmdb.gz" | gunzip > "$tmp" 2>/dev/null; then
      downloaded="$month"
      break
    fi
  done
  if [ -z "$downloaded" ]; then
    rm -f "$tmp"
    echo "Nenhuma versão de $name encontrada para $current ou $previous." >&2
    exit 1
  fi
  if ! tail -c 131072 "$tmp" | grep -aq "MaxMind.com"; then
    rm -f "$tmp"
    echo "$name-$downloaded não parece um ficheiro .mmdb válido." >&2
    exit 1
  fi
  mv -f "$tmp" "$dir/$name.mmdb"
  echo "$name: versão $downloaded, $(du -h "$dir/$name.mmdb" | cut -f1)"
done
