# Reproducible Network Intrusion Detection & C2 Threat Hunting Lab

An enterprise-grade, offline-capable threat hunting framework that ingests PCAP captures, executes Zeek and Suricata protocol parsing, performs statistical C2 beaconing analysis with mathematical jitter curve-fitting, extracts STIX 2.1 / MISP threat intelligence, and produces auditable executive and technical reports.

```
                    +-------------------------------------+
                    |       Static PCAP Artifact          |
                    +------------------+------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
     +---------------------------+           +---------------------------+
     |   Zeek Security Engine    |           |    Suricata IDS Engine    |
     | (JA3, SumStats, Custom)   |           |  (EVE JSON, JA3/4, Rules) |
     +-------------+-------------+           +-------------+-------------+
                   |                                       |
                   |   conn.log / ssl.log / dns.log        | eve.json
                   +-------------------+-------------------+
                                       |
                                       v
                   +---------------------------------------+
                   |     Python Analysis Pipeline          |
                   | - Inter-arrival Delta Analysis        |
                   | - Sleep / Jitter Grid Curve Fitting   |
                   | - IOC Extraction & STIX/MISP Export   |
                   +-------------------+-------------------+
                                       |
            +--------------------------+--------------------------+
            |                          |                          |
            v                          v                          v
+-----------------------+  +-----------------------+  +-----------------------+
| Threat Report & IOCs  |  | Zeek Intel Framework  |  | ATT&CK Matrix Mapping |
| (REPORT.md, iocs.csv) |  |   (intel/intel.dat)   |  |   (ATTACK_MATRIX.md)  |
+-----------------------+  +-----------------------+  +-----------------------+
```

## Quickstart Guide

```bash
# 1. Clone repository and initialize environment
git clone https://github.com/varuvedika-sys/Net-threat-lab.git && cd Net-threat-lab

# 2. Install required Python dependencies
pip install numpy pandas scipy pytest pyyaml

# 3. Fetch static sample PCAPs and populate sample manifest
./scripts/fetch_samples.sh

# 4. Execute automated beaconing analysis, IOC extraction, and report generation
python3 -m analysis.beaconing --sample-id cobaltstrike-20240115
python3 -m analysis.iocs --sample-id cobaltstrike-20240115
python3 -m analysis.report --sample-id cobaltstrike-20240115

# 5. Inspect generated threat hunting report
cat out/cobaltstrike-20240115/REPORT.md
```

## Sample Findings Index

| Sample ID | Malware Family | Target Domain / C2 IP | Sleep / Jitter | Score | Primary Finding Takeaway |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `cobaltstrike-20240115` | Cobalt Strike | `update.edge-cloud-cdn.com` / `192.168.5.112` | 60s / 20% | 0.92 | Malleable HTTP POST C2 beaconing with SSL/TLS SNI mismatch on port 8443. |
| `cobaltstrike-20240320` | Cobalt Strike | `dns.telemetry-host.org` / `10.0.2.15` | 30s / 10% | 0.88 | High-entropy DNS sub-domain tunneling and rare JA3 hash (`e7d705a3...`). |
| `qakbot-20231102` | Qakbot | `92.118.151.9` | 120s / 30% | 0.81 | HTTPS C2 using short-lived self-signed certificate (3 days) on non-standard port 4433. |
| `icedid-20231205` | IcedID | `app-data-sync.net` / `185.220.101.5` | 300s / 0% | 0.95 | Rigid machine-regular TLS beaconing sharing identical JA3S with Cobalt Strike sample. |

---

## Web & Application Security Hardening Checklist

When deploying interactive web visualization services (e.g., Arkime, Kibana) or API interfaces alongside analysis labs, strictly enforce the following baseline security controls:

* **Secrets & Credentials**: Store all tokens, keys, and credentials in external `.env` files. Ensure `.env` is listed in `.gitignore` and never committed.
* **Authentication & Access Control**: Protect all administrative and API routes with multi-factor authentication (MFA) and explicit Role-Based Access Control (RBAC).
* **Input Sanitization**: Validate and sanitize all user input server-side. Enforce strict Content Security Policy (CSP) headers to prevent Cross-Site Scripting (XSS).
* **Rate Limiting**: Enforce token-bucket or leaky-bucket rate limiting on API endpoints to prevent brute-force attacks and resource exhaustion.
* **CORS & Security Headers**: Restrict CORS `Access-Control-Allow-Origin` to trusted origins. Set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security`.
* **Production State**: Turn off all developer debug modes, diagnostic endpoints, and verbose error stack traces in production environments.
* **Dependency Management**: Pin dependency versions in lockfiles. Regularly execute `npm audit` or `pip-audit` to remediate vulnerabilities.
* **Database Security**: Enforce parameterised SQL/NoSQL queries. Store user passwords using Argon2id or bcrypt with a high work factor.
* **Secret Scanning**: Regularly run `gitleaks` or `trufflehog` across full Git commit history to detect leaked credentials.
