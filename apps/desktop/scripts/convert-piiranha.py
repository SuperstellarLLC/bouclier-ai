#!/usr/bin/env python3
"""
Convert iiiorg/piiranha-v1-detect-personal-information (mDeBERTa-v3-base,
~280 MB, 17 PII classes × 6 languages) to CoreML for on-device PII
detection inside the Bouclier macOS app.

This is the Phase 2 follow-up to Prompt Guard 2 conversion. The
architectural pattern is identical — same DeBERTa monkey-patches, same
sqrt-op workaround, same INT8 weight quantization — but the model is
TOKEN classification (per-subword tag) rather than SEQUENCE
classification (single binary).

Usage:
    cd apps/desktop
    source .venv-ml/bin/activate    # reuse the venv from Prompt Guard
    huggingface-cli login           # Piiranha is publicly downloadable
                                    # but rate-limited without auth
    python3 scripts/convert-piiranha.py

Outputs:
    Sources/Bouclier/Resources/Piiranha.mlpackage
    Sources/Bouclier/Resources/PiiranhaTokenizer/

Eval target (from the model card): 93.1% F1 on 17 PII classes, 98.5%
binary detection, 6 languages. Real-world chat F1 expected lower per
the "Unmasking the Reality of PII Masking Models" paper
(https://arxiv.org/abs/2504.12308). See PRvL harness in
`scripts/bench-piiranha.py` (Phase 2 scaffolding) for our actual
out-of-distribution numbers.
"""

import shutil
import sys
from pathlib import Path

import torch
from huggingface_hub import snapshot_download
from transformers import AutoModelForTokenClassification, AutoTokenizer

MODEL_ID = "iiiorg/piiranha-v1-detect-personal-information"
SEQ_LENGTH = 256  # piiranha's published context window

SCRIPT_DIR = Path(__file__).resolve().parent
RESOURCES_DIR = SCRIPT_DIR.parent / "Sources" / "Bouclier" / "Resources"
MODEL_OUTPUT = RESOURCES_DIR / "Piiranha.mlpackage"
TOKENIZER_OUTPUT = RESOURCES_DIR / "PiiranhaTokenizer"
LABEL_MAP_OUTPUT = RESOURCES_DIR / "piiranha-labels.json"


class PiiranhaWrapper(torch.nn.Module):
    """HuggingFace token-classification models return a dataclass with
    `.logits` of shape [B, L, num_labels]. CoreML wants a raw tensor."""

    def __init__(self, model: torch.nn.Module) -> None:
        super().__init__()
        self.model = model

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


def download_tokenizer_files() -> None:
    print(f"[1/5] Downloading tokenizer files to {TOKENIZER_OUTPUT}")
    if TOKENIZER_OUTPUT.exists():
        shutil.rmtree(TOKENIZER_OUTPUT)
    TOKENIZER_OUTPUT.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=MODEL_ID,
        local_dir=str(TOKENIZER_OUTPUT),
        allow_patterns=[
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "special_tokens_map.json",
            "spm.model",
            "sentencepiece.bpe.model",
        ],
    )
    print(f"      → {sorted(p.name for p in TOKENIZER_OUTPUT.iterdir())}")

    # Same swift-transformers AutoTokenizer routing trick as Prompt Guard.
    # DeBERTaV2Tokenizer isn't in the registry; the Unigram SPM under the
    # hood is what T5Tokenizer (in swift-transformers) handles. Re-tagging
    # avoids the runtime "tokenizer_class not found" failure.
    import json as _json
    tok_config = TOKENIZER_OUTPUT / "tokenizer_config.json"
    if tok_config.exists():
        data = _json.loads(tok_config.read_text())
        if data.get("tokenizer_class") == "DebertaV2Tokenizer":
            data["tokenizer_class"] = "T5Tokenizer"
            tok_config.write_text(_json.dumps(data, indent=2))
            print("      → rewrote tokenizer_class: DebertaV2Tokenizer → T5Tokenizer")


def export_label_map(model) -> None:
    """Save the id-to-label map so the Swift side can decode logits
    without re-downloading the model.

    Piiranha's labels look like B-EMAIL / I-EMAIL / B-PHONE / O — IOB2
    tagging. The Swift PIIClassifier (Phase 2) will collapse these to
    the same entity-type slugs used by `PIIScanner`. The mapping from
    Piiranha labels to our internal `PIIEntityType` is documented in
    Sources/Bouclier/Proxy/PIIClassifier.swift (Phase 2)."""
    import json as _json
    print(f"[2/5] Exporting id-to-label map to {LABEL_MAP_OUTPUT}")
    cfg = model.config
    label_map = {int(k): v for k, v in cfg.id2label.items()}
    LABEL_MAP_OUTPUT.write_text(_json.dumps(label_map, indent=2))
    print(f"      → {len(label_map)} labels exported")


def load_model() -> tuple[PiiranhaWrapper, dict, "torch.nn.Module"]:
    print(f"[3/5] Loading {MODEL_ID}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_ID)
    model.eval()
    export_label_map(model)

    wrapper = PiiranhaWrapper(model)
    wrapper.eval()
    dummy = tokenizer(
        "test prompt with PII like alice@example.com",
        return_tensors="pt",
        max_length=SEQ_LENGTH,
        padding="max_length",
        truncation=True,
    )
    return wrapper, dummy, model


# The DeBERTa monkey-patches and sqrt-op workaround are identical to the
# Prompt Guard converter. We import them from there to avoid duplication.
# If you're reading this and the import doesn't work because the patch
# functions aren't exposed, look at convert-promptguard.py for the
# implementation — it's the same 6 helpers and the same coremltools sqrt
# override. Both functions are idempotent.

def patch_deberta_and_coremltools() -> None:
    print("[4/5] Patching DeBERTa scripted helpers + coremltools sqrt op")
    # Import lazily so users without coremltools can still run the
    # tokenizer-download stage to inspect what would be exported.
    sys.path.insert(0, str(SCRIPT_DIR))
    # The two functions below live in convert-promptguard.py; we shell
    # out to them so this script stays small and the patch logic stays
    # in one place. If you split the package_id resolver into its own
    # module later, replace this with a clean import.
    import importlib.util
    pg_path = SCRIPT_DIR / "convert-promptguard.py"
    spec = importlib.util.spec_from_file_location("_pg", pg_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load convert-promptguard.py for patch reuse")
    pg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pg)
    pg.patch_deberta_scripted_helpers()
    pg.patch_coremltools_sqrt()


def convert_and_quantize(wrapper: PiiranhaWrapper, dummy: dict) -> bool:
    print("[5/5] Tracing → CoreML → INT8 quantize")
    try:
        import coremltools as ct
    except ImportError:
        print("      ! coremltools not installed. pip install coremltools")
        return False

    try:
        with torch.no_grad():
            traced = torch.jit.trace(
                wrapper,
                (dummy["input_ids"], dummy["attention_mask"]),
                strict=False,
            )

        mlmodel = ct.convert(
            traced,
            inputs=[
                ct.TensorType(name="input_ids", shape=(1, SEQ_LENGTH), dtype=int),
                ct.TensorType(name="attention_mask", shape=(1, SEQ_LENGTH), dtype=int),
            ],
            outputs=[ct.TensorType(name="logits")],
            compute_precision=ct.precision.FLOAT16,
            compute_units=ct.ComputeUnit.ALL,
            minimum_deployment_target=ct.target.macOS15,
            convert_to="mlprogram",
        )
    except Exception as exc:  # noqa: BLE001
        print(f"      ! conversion failed: {exc}")
        return False

    try:
        from coremltools.optimize.coreml import (
            OpLinearQuantizerConfig,
            OptimizationConfig,
            linear_quantize_weights,
        )
        config = OptimizationConfig(
            global_config=OpLinearQuantizerConfig(
                mode="linear_symmetric",
                dtype="int8",
                granularity="per_channel",
            )
        )
        mlmodel = linear_quantize_weights(mlmodel, config=config)
    except Exception as exc:  # noqa: BLE001
        print(f"      ! quantization failed, saving FP32: {exc}")

    if MODEL_OUTPUT.exists():
        shutil.rmtree(MODEL_OUTPUT)
    mlmodel.save(str(MODEL_OUTPUT))

    size_bytes = sum(f.stat().st_size for f in MODEL_OUTPUT.rglob("*") if f.is_file())
    print(f"      → saved {MODEL_OUTPUT} ({size_bytes / (1024 * 1024):.1f} MB)")
    return True


def main() -> int:
    if not RESOURCES_DIR.exists():
        print(f"! Resources dir not found: {RESOURCES_DIR}", file=sys.stderr)
        return 1
    download_tokenizer_files()
    patch_deberta_and_coremltools()
    wrapper, dummy, _model = load_model()
    if not convert_and_quantize(wrapper, dummy):
        return 1
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
