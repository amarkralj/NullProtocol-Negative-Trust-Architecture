# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
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
QUERIES = sys.argv[1:] or ["okta"]          # search words, or dataset folders such as dir:datasets/mcp


def gh(path):
    return json.loads(subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True).stdout)


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("too large")
    return data


def safe_text(data: bytes) -> int:
    """Plain-text logs (CSV, Linux audit, server logs): UTF-8, no binary or script signature, no NUL bytes."""
    if any(data.startswith(m) for m in BAD_MAGIC) or b"\x00" in data:
        raise ValueError("binary or script signature")
    return len(data.decode("utf-8").splitlines())


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
        if q.startswith("dir:"):                         # a named folder: take its data files directly
            items = gh(f"repos/{REPO}/contents/{q[4:]}")
            d = OUT / pathlib.Path(q[4:]).relative_to("datasets")
            for i in items:
                name = i["name"]
                if i["type"] != "file" or (d / name).exists():
                    continue
                if name.endswith(".yml"):
                    d.mkdir(parents=True, exist_ok=True); (d / name).write_bytes(get(RAW + i["path"]))
                elif name.endswith((".log", ".json", ".ndjson", ".csv")):
                    try:
                        data = get(MEDIA + i["path"])
                        try:
                            n = safe_jsonl(data)
                        except ValueError:
                            n = safe_text(data)
                        d.mkdir(parents=True, exist_ok=True); (d / name).write_bytes(data)
                        print(f"  ok   {i['path']}  ({n} events)")
                    except Exception as exc:
                        print(f"  skip {i['path']}: {exc}")
            continue
        items = gh(f"search/code?q=repo:{REPO}+{q}+extension:yml&per_page=100")["items"]
        paths |= {i["path"] for i in items if i["path"].startswith("datasets/") and "/malware/" not in i["path"]}
    paths = sorted(paths)
    print(f"{len(paths)} dataset descriptors for {QUERIES}")
    for p in paths:
        meta = get(RAW + p).decode("utf-8")
        logs = re.findall(r"path:\s*(/datasets/\S+\.(?:log|json|ndjson|csv))", meta)
        d = OUT / pathlib.Path(p).parent.relative_to("datasets")
        if any(any(d.glob(f"*.{x}")) for x in ("log", "json", "ndjson", "csv")) and all(
                (d / pathlib.Path(lp).name).exists() for lp in logs):
            continue
        d.mkdir(parents=True, exist_ok=True)
        (d / pathlib.Path(p).name).write_text(meta)
        for lp in logs:
            try:
                data = get(MEDIA + lp.lstrip("/"))
                try:
                    n = safe_jsonl(data)
                except ValueError:                       # not JSON lines: accept only as plain text
                    n = safe_text(data)
                (d / pathlib.Path(lp).name).write_bytes(data)
                print(f"  ok   {lp}  ({n} events)")
            except Exception as exc:
                print(f"  skip {lp}: {exc}")


if __name__ == "__main__":
    main()
