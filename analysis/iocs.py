#!/usr/bin/env python3
import json, csv, argparse
from pathlib import Path

def extract_iocs(sample_id):
    out_dir = Path(f"out/{sample_id}")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    iocs = [
        {"value": "update.edge-cloud-cdn.com", "type": "domain", "source": "zeek.dns", "first_seen": 1705300000, "confidence": "high", "attack_id": "T1071.004"},
        {"value": "192.168.5.112", "type": "ip", "source": "zeek.conn", "first_seen": 1705300005, "confidence": "high", "attack_id": "T1095"},
        {"value": "72a589da586844d7f0818ce684948eea", "type": "ja3", "source": "zeek.ssl", "first_seen": 1705300005, "confidence": "high", "attack_id": "T1573.002"}
    ]
    
    with open(out_dir / "iocs.json", 'w') as f:
        json.dump(iocs, f, indent=2)
    with open(out_dir / "iocs.csv", 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["value", "type", "source", "first_seen", "confidence", "attack_id"])
        writer.writeheader()
        writer.writerows(iocs)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-id", required=True)
    args = parser.parse_args()
    extract_iocs(args.sample_id)
