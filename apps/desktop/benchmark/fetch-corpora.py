#!/usr/bin/env python3
"""Fetch public, third-party prompt-injection corpora for the external
benchmark (ExternalBenchmarkTests). Writes benchmark/data/{attacks,benign}.jsonl
as {"text","label","src"} lines. Data is gitignored — this script makes the
run reproducible without vendoring third-party datasets of varying licence.

Corpora (all public via the HF datasets-server, no auth):
  - deepset/prompt-injections          — mixed direct-injection/jailbreak + benign.
                                          NOTE: labels DIRECT jailbreak/role-play
                                          as "injection"; that is NOT Bouclier's
                                          threat model, so its attack split scores
                                          low by design (out of class).
  - Lakera/gandalf_ignore_instructions — instruction-override payloads, i.e.
                                          Bouclier's actual target class.
  - leolee99/NotInject                 — benign prompts loaded with trigger words,
                                          the over-defense stress test.

Usage:  python3 benchmark/fetch-corpora.py
Then:   BOUCLIER_BENCH=1 swift test --filter ExternalBenchmarkTests
"""
import json
import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data")
os.makedirs(OUT, exist_ok=True)


def rows(ds, split, config="default"):
    out, off = [], 0
    while True:
        u = (f"https://datasets-server.huggingface.co/rows?dataset={ds}"
             f"&config={config}&split={split}&offset={off}&length=100")
        try:
            d = json.load(urllib.request.urlopen(u, timeout=30))
        except Exception as e:
            print(f"  fetch error {ds}/{split}@{off}: {str(e)[:80]}")
            break
        rs = d.get("rows", [])
        if not rs:
            break
        out += [r["row"] for r in rs]
        off += len(rs)
        if off >= d.get("num_rows_total", 0):
            break
    return out


def splits(ds):
    try:
        d = json.load(urllib.request.urlopen(
            f"https://datasets-server.huggingface.co/splits?dataset={ds}", timeout=20))
        return [(s["config"], s["split"]) for s in d["splits"]]
    except Exception as e:
        print(f"  splits error {ds}: {str(e)[:80]}")
        return []


def first_text_key(row):
    for k in ("text", "prompt", "content"):
        if k in row:
            return k
    return next(iter(row))


attacks, benign = [], []

# deepset — split by label (1=injection, 0=benign)
dp = []
for _, sp in splits("deepset/prompt-injections") or [("default", "train"), ("default", "test")]:
    dp += rows("deepset/prompt-injections", sp)
attacks += [{"text": r["text"], "label": "attack", "src": "deepset"}
            for r in dp if str(r.get("label")) == "1" and r.get("text")]
benign += [{"text": r["text"], "label": "benign", "src": "deepset"}
           for r in dp if str(r.get("label")) == "0" and r.get("text")]

# gandalf — instruction-override injections (Bouclier's target class)
for cfg, sp in splits("Lakera/gandalf_ignore_instructions"):
    r = rows("Lakera/gandalf_ignore_instructions", sp, cfg)
    if r:
        k = first_text_key(r[0])
        attacks += [{"text": x[k], "label": "attack", "src": "gandalf"} for x in r if x.get(k)]

# NotInject — over-defense (benign with trigger words)
for cfg, sp in splits("leolee99/NotInject"):
    r = rows("leolee99/NotInject", sp, cfg)
    if r:
        k = first_text_key(r[0])
        benign += [{"text": x[k], "label": "benign", "src": "notinject"} for x in r if x.get(k)]
        break


def dump(name, items):
    with open(os.path.join(OUT, name), "w") as f:
        for it in items:
            f.write(json.dumps(it) + "\n")


dump("attacks.jsonl", attacks)
dump("benign.jsonl", benign)
from collections import Counter
print("attacks.jsonl:", len(attacks), dict(Counter(a["src"] for a in attacks)))
print("benign.jsonl :", len(benign), dict(Counter(b["src"] for b in benign)))
