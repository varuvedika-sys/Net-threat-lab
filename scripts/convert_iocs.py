#!/usr/bin/env python3
import csv, sys

if len(sys.argv) < 3:
    sys.exit(1)

rules = []
sid = 9100000

with open(sys.argv[1], 'r') as f:
    for row in csv.DictReader(f):
        t, v = row.get("type", "").lower(), row.get("value", "")
        sid += 1
        if t == "domain":
            rules.append(f'alert dns $HOME_NET any -> any any (msg:"AUTO IOC Domain Match {v}"; dns.query; content:"{v}"; classtype:trojan-activity; sid:{sid}; rev:1;)')
        elif t == "ip":
            rules.append(f'alert ip $HOME_NET any -> [{v}] any (msg:"AUTO IOC IP Match {v}"; classtype:trojan-activity; sid:{sid}; rev:1;)')

with open(sys.argv[2], 'w') as f:
    f.write("# Auto-generated IOC Rules\n" + "\n".join(rules) + "\n")
