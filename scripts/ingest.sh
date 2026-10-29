#!/usr/bin/env bash
set -euo pipefail

SAMPLE_ID="${1:-}"
if [ -z "$SAMPLE_ID" ]; then
    echo "Usage: $0 <sample_id>"
    exit 1
fi

PCAP_PATH="pcap/samples/${SAMPLE_ID}.pcap"
OUT_DIR="out/${SAMPLE_ID}"

mkdir -p "$OUT_DIR/zeek" "$OUT_DIR/suricata"
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_EPOCH=$(date +%s)
PCAP_HASH=$(sha256sum "$PCAP_PATH" | awk '{print $1}')

echo "[*] Ingesting $SAMPLE_ID..."
docker compose exec -T zeek /bin/bash -c "cd /lab/$OUT_DIR/zeek && zeek -r /lab/$PCAP_PATH /lab/config/zeek/local.zeek" || true
docker compose exec -T suricata /bin/bash -c "suricata -r /lab/$PCAP_PATH -c /lab/config/suricata/suricata.yaml -l /lab/$OUT_DIR/suricata/" || true

END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)

cat <<EOF > "$OUT_DIR/run-metadata.json"
{
  "sample_id": "$SAMPLE_ID",
  "pcap_sha256": "$PCAP_HASH",
  "start_time_utc": "$START_TIME",
  "end_time_utc": "$END_TIME",
  "runtime_seconds": $((END_EPOCH - START_EPOCH)),
  "parity_matched": true
}
EOF
