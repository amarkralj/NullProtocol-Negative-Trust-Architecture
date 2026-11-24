"""Development aid: which Panther test logs (positives) produce no events, grouped by family and operation."""
import json, yaml, collections, sys
from npcore import sources
pre = json.load(open("results/v11_panther_expected.json"))["rules"]
gaps = collections.defaultdict(collections.Counter)
for path, exp in pre.items():
    if not isinstance(exp, list):
        continue
    fam = path.split("/")[1]
    if len(sys.argv) > 1 and fam not in sys.argv[1:]:
        continue
    for t in yaml.safe_load(open("data/panther/" + path)).get("Tests") or []:
        if not t.get("ExpectedResult"):
            continue
        log = t.get("Log") or {}
        if isinstance(log, str):
            try: log = json.loads(log)
            except ValueError: continue
        try:
            ok = bool(sources.convert(log))
        except Exception as ex:
            ok = False; gaps[fam]["ERROR " + type(ex).__name__ + " " + str(ex)[:50]] += 1; continue
        if not ok:
            op = log.get("eventName") or log.get("eventType") or log.get("action") or log.get("name") or \
                (log.get("protoPayload") or {}).get("methodName") or log.get("operationName") or \
                (f"{log.get('verb')} {(log.get('objectRef') or {}).get('resource')}/{(log.get('objectRef') or {}).get('subresource','')}" if "verb" in log else str(sorted(log))[:60])
            gaps[fam][str(op)[:70]] += 1
for fam, c in gaps.items():
    print("==", fam, sum(c.values()))
    for op, n in c.most_common(int(__import__("os").environ.get("TOP", "25"))):
        print(f"   {n:3d} {op}")
