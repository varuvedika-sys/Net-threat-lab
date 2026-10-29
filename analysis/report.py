#!/usr/bin/env python3
import json, csv, argparse
from pathlib import Path

def generate_report(sample_id):
    out_dir = Path(f"out/{sample_id}")
    report_md = f"# Automated Threat Investigation Report\n**Sample ID**: `{sample_id}`\n"
    with open(out_dir / "REPORT.md", "w") as f:
        f.write(report_md)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-id", required=True)
    args = parser.parse_args()
    generate_report(args.sample_id)
