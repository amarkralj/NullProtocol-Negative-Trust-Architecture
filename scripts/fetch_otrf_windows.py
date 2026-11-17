# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Download the Windows host datasets of OTRF Security-Datasets (MIT, https://github.com/OTRF/Security-Datasets).

Safety: only datasets/atomic/windows/*/host/*.zip from the official repository; each zip is opened in Python and only
JSON members with safe names and sizes are written (anything else is refused); the zip itself is not kept. Nothing is
executed. Output: data/otrf/windows/<tactic>/<dataset>.json (data/ is git-ignored).
"""
import io, json, pathlib, subprocess, urllib.request, zipfile

RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
OUT = pathlib.Path("data/otrf/windows")
MAX = 300_000_000


def main():
    tree = json.loads(subprocess.run(["gh", "api", "repos/OTRF/Security-Datasets/git/trees/master?recursive=1"],
                                     capture_output=True, text=True, check=True).stdout)["tree"]
    paths = [t["path"] for t in tree if t["type"] == "blob" and t["path"].startswith("datasets/atomic/windows/")
             and "/host/" in t["path"] and t["path"].endswith(".zip")]
    print(len(paths), "host datasets")
    for p in paths:
        tactic, name = p.split("/")[3], pathlib.Path(p).stem
        dst = OUT / tactic / f"{name}.json"
        if dst.exists():
            continue
        with urllib.request.urlopen(RAW + p, timeout=120) as r:
            blob = r.read(60_000_000)
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile:
            print("  skip (not a zip)", p); continue
        members = [i for i in zf.infolist() if not i.is_dir()]
        bad = [i.filename for i in members if not i.filename.lower().endswith(".json") or ".." in i.filename
               or i.filename.startswith("/") or i.file_size > MAX]
        if bad or not members:
            print("  refused", p, bad[:3]); continue
        parts = []
        for i in members:
            data = zf.read(i)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:                       # some exports are Latin-1 text
                data = data.decode("latin-1").encode("utf-8")
            parts.append(data if data.endswith(b"\n") else data + b"\n")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b"".join(parts))
        print("  ok", tactic, name)


if __name__ == "__main__":
    main()
