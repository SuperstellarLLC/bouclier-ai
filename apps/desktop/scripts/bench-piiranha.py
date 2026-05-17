#!/usr/bin/env python3
"""
Benchmark harness for the Phase 2 PII detection layer.

Loads the converted Piiranha CoreML model alongside the still-shipping
regex tier (via `packages/patterns`) and computes per-entity-type F1
on AI4Privacy `pii-masking-300k` plus PRvL out-of-distribution
adversarial samples. Output is a markdown table the team can paste
into a release note or a procurement-questionnaire response.

The point of this harness is *not* to maximize F1 on the published
benchmark — it's to catch the failure mode flagged by the S-tier
review: "real-world chat F1 is probably 70–80, not 93." Run this
before locking Phase 2 model choice; if Piiranha underperforms
GLiNER-multi-PII or OpenAI Privacy Filter on our adversarial slice,
the plug-in `MLClassifier` slot is the cleanest swap.

Usage:
    cd apps/desktop
    source .venv-ml/bin/activate
    pip install datasets seqeval pandas
    python3 scripts/bench-piiranha.py \\
        --model Sources/Bouclier/Resources/Piiranha.mlpackage \\
        --tokenizer Sources/Bouclier/Resources/PiiranhaTokenizer \\
        --dataset ai4privacy/pii-masking-300k \\
        --split validation \\
        --limit 1000

References:
- AI4Privacy: https://huggingface.co/datasets/ai4privacy/pii-masking-300k
- PRvL: https://arxiv.org/abs/2508.05545
- "Unmasking the Reality of PII Masking Models": https://arxiv.org/abs/2504.12308
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", required=True, type=Path)
    p.add_argument("--tokenizer", required=True, type=Path)
    p.add_argument("--dataset", default="ai4privacy/pii-masking-300k")
    p.add_argument("--split", default="validation")
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--adversarial", type=Path, default=None,
                   help="Optional JSONL with our internal hard cases.")
    p.add_argument("--out", type=Path, default=Path("bench-piiranha-results.md"))
    return p.parse_args()


def load_corpus(dataset: str, split: str, limit: int) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError:
        print("! datasets not installed. pip install datasets", file=sys.stderr)
        sys.exit(1)
    ds = load_dataset(dataset, split=split)
    return [dict(row) for row in ds.select(range(min(limit, len(ds))))]


def load_adversarial(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def detect_with_piiranha(samples: Iterable[dict], model_path: Path, tokenizer_path: Path) -> list[set[str]]:
    """Run inference with the CoreML model and emit per-sample
    predicted entity-type sets. Stub structure shown — fill in with the
    actual coremltools / transformers boilerplate when Phase 2 lands."""
    try:
        import coremltools as ct
        from transformers import AutoTokenizer
    except ImportError:
        print("! Install coremltools + transformers to bench.", file=sys.stderr)
        sys.exit(1)

    tokenizer = AutoTokenizer.from_pretrained(str(tokenizer_path))
    model = ct.models.MLModel(str(model_path))
    # Label map written by convert-piiranha.py
    label_map_path = model_path.parent / "piiranha-labels.json"
    id2label = {int(k): v for k, v in json.loads(label_map_path.read_text()).items()}

    preds: list[set[str]] = []
    for row in samples:
        text = row.get("source_text") or row.get("text") or row["unmasked_text"]
        encoded = tokenizer(text, return_tensors="np", max_length=256, padding="max_length", truncation=True)
        out = model.predict({
            "input_ids": encoded["input_ids"].astype("int32"),
            "attention_mask": encoded["attention_mask"].astype("int32"),
        })
        logits = out["logits"][0]  # [L, num_labels]
        ids = logits.argmax(-1)
        labels = {id2label[int(i)] for i in ids if id2label[int(i)] != "O"}
        # Strip B-/I- prefix.
        normalized = {l.split("-", 1)[-1] for l in labels}
        preds.append(normalized)
    return preds


def gold_entity_types(row: dict) -> set[str]:
    spans = row.get("privacy_mask") or row.get("entities") or []
    return {span.get("label") or span.get("type") for span in spans if span}


def compute_per_type_prf(samples: list[dict], preds: list[set[str]]) -> dict[str, tuple[float, float, float]]:
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    for row, pred in zip(samples, preds):
        gold = gold_entity_types(row)
        for t in pred & gold: tp[t] += 1
        for t in pred - gold: fp[t] += 1
        for t in gold - pred: fn[t] += 1
    out: dict[str, tuple[float, float, float]] = {}
    for t in set(tp) | set(fp) | set(fn):
        p = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else 0.0
        r = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        out[t] = (p, r, f1)
    return out


def write_markdown(stats: dict[str, tuple[float, float, float]], out_path: Path) -> None:
    rows = ["| Entity | Precision | Recall | F1 |", "| --- | --- | --- | --- |"]
    for t, (p, r, f1) in sorted(stats.items(), key=lambda kv: -kv[1][2]):
        rows.append(f"| {t} | {p:.3f} | {r:.3f} | {f1:.3f} |")
    macro_f1 = sum(f for _, _, f in stats.values()) / len(stats) if stats else 0.0
    rows.append(f"\n**Macro F1:** {macro_f1:.3f} across {len(stats)} entity types")
    out_path.write_text("\n".join(rows))
    print(f"→ wrote {out_path}")


def main() -> int:
    args = parse_args()
    samples = load_corpus(args.dataset, args.split, args.limit)
    samples += load_adversarial(args.adversarial) if args.adversarial else []
    print(f"Loaded {len(samples)} samples")
    preds = detect_with_piiranha(samples, args.model, args.tokenizer)
    stats = compute_per_type_prf(samples, preds)
    write_markdown(stats, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
