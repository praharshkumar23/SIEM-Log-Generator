#!/usr/bin/env python3
"""
Convert JSON logs to CSV format
Author: Praharsh Kumar
"""

import json
import csv
import os

input_file = "output/praharsh_siem_logs_3000.json"
output_file = "output/praharsh_siem_logs_3000.csv"

print("🔄 Converting JSON logs to CSV...")

with open(input_file, "r", encoding="utf-8") as f:
    logs = json.load(f)

print(f"📥 Loaded {len(logs)} logs from {input_file}")

all_keys = set()
for log in logs:
    all_keys.update(log.keys())
all_keys = sorted(all_keys)

print(f"📋 Fields detected: {len(all_keys)}")

with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=all_keys)
    writer.writeheader()
    for log in logs:
        writer.writerow({k: log.get(k, "") for k in all_keys})

print(f"✅ Successfully converted {len(logs)} logs to CSV!")
print(f"📁 Output: {output_file}")
