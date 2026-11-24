#!/usr/bin/env bash
# Inside the lab VM: package the API audit log and the labels. Nothing else leaves the VM.
set -euo pipefail
out=/tmp/lab-run-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
tar -czf "$out" -C /opt/lab audit/audit.log labels.jsonl
sha256sum "$out"; echo "copy it out from the Mac with: scp <user>@<vm-ip>:$out ."
