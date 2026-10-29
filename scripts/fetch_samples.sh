#!/usr/bin/env bash
set -euo pipefail

SAMPLE_DIR="pcap/samples"
MANIFEST="pcap/manifest.yaml"
mkdir -p "$SAMPLE_DIR"

echo "[*] Checking PCAP sample availability..."
SAMPLE_IDS=$(grep -E '^\s*- id:' "$MANIFEST" | awk '{print $3}')

for id in $SAMPLE_IDS; do
    pcap_path="$SAMPLE_DIR/${id}.pcap"
    if [ ! -f "$pcap_path" ]; then
        echo "[*] Creating synthetic PCAP for sample: $id"
        python3 -c "
import struct
pcap_hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
pkt_hdr = struct.pack('<IIII', 1705300000, 0, 54, 54)
eth_ip_tcp = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00' + b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xcd\x0a\x00\x02\x0f\xc0\xa8\x05\x70' + b'\x04\xd2\x1f\x90\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00'
with open('$pcap_path', 'wb') as f:
    f.write(pcap_hdr)
    for i in range(20):
        f.write(struct.pack('<IIII', 1705300000 + i*60, 0, 54, 54))
        f.write(eth_ip_tcp)
"
    fi
    sha256=$(sha256sum "$pcap_path" | awk '{print $1}')
    echo "[+] Sample $id ready (SHA256: ${sha256:0:12}...)"
done
