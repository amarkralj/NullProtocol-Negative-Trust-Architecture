# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Download selected identity attack logs from splunk/attack_data (Apache-2.0, https://github.com/splunk/attack_data).

Safety: only dataset descriptor files (.yml) and the log files they name are fetched, only from the official repository,
only text. Every file is checked: no executable or archive signatures, valid JSON lines, size limit. Nothing is run.
Files go to data/splunk_attack_data/<technique>/<dataset>/ (data/ is git-ignored).
"""
import json, pathlib, re, subprocess, sys, urllib.request

REPO = "splunk/attack_data"
RAW = "https://raw.githubusercontent.com/splunk/attack_data/master/"
MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
OUT = pathlib.Path("data/splunk_attack_data")
MAX_BYTES = 50_000_000
BAD_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"#!")
QUERIES = sys.argv[1:] or ["okta"]


def gh(path):
    return json.loads(subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True).stdout)


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("too large")
    return data


def safe_jsonl(data: bytes) -> int:
    if data[:4].startswith(BAD_MAGIC) or any(data.startswith(m) for m in BAD_MAGIC):
        raise ValueError("binary or script signature")
    text = data.decode("utf-8")                      # raises on binary
    n = 0
    for line in text.splitlines():
        if line.strip():
            json.loads(line); n += 1
    return n


def main():
    paths = set()
    for q in QUERIES:
        items = gh(f"search/code?q=repo:{REPO}+{q}+extension:yml&per_page=100")["items"]
        paths |= {i["path"] for i in items if i["path"].startswith("datasets/") and "/malware/" not in i["path"]}
    paths = sorted(paths)
    print(f"{len(paths)} dataset descriptors for {QUERIES}")
    for p in paths:
        meta = get(RAW + p).decode("utf-8")
        logs = re.findall(r"path:\s*(/datasets/\S+\.(?:log|json))", meta)
        d = OUT / pathlib.Path(p).parent.relative_to("datasets")
        if any(d.glob("*.log")) or any(d.glob("*.json")):
            continue
        d.mkdir(parents=True, exist_ok=True)
        (d / pathlib.Path(p).name).write_text(meta)
        for lp in logs:
            try:
                data = get(MEDIA + lp.lstrip("/"))
                n = safe_jsonl(data)
                (d / pathlib.Path(lp).name).write_bytes(data)
                print(f"  ok   {lp}  ({n} events)")
            except Exception as exc:
                print(f"  skip {lp}: {exc}")


if __name__ == "__main__":
    main()
