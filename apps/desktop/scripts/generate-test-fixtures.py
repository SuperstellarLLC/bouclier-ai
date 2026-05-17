#!/usr/bin/env python3
"""
Generate deterministic media fixtures used by Bouclier's Swift tests.

Outputs go to apps/desktop/Tests/BouclierTests/Fixtures/. Every artefact
is reproducible: same inputs, same bytes. The Swift tests pull them in
via Bundle.module so they ship with the package's test target without
us having to commit binary blobs that drift.

Run from apps/desktop/:
    source .venv-ml/bin/activate
    python3 scripts/generate-test-fixtures.py

Adds ~30 KB of assets to git. Re-runs are idempotent.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SCRIPT_DIR = Path(__file__).resolve().parent
OUT_DIR = SCRIPT_DIR.parent / "Tests" / "BouclierTests" / "Fixtures"


def _font(size: int) -> ImageFont.FreeTypeFont:
    # macOS-standard system font path; falls back to PIL default if
    # missing so the script is portable.
    candidates = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for c in candidates:
        if Path(c).exists():
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


def write_image(name: str, img: Image.Image, fmt: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    img.save(path, fmt)
    print(f"  → {name} ({path.stat().st_size:,} bytes)")


def text_image_png(text: str, size: tuple[int, int] = (480, 240)) -> Image.Image:
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    font = _font(28)
    # Multi-line aware: split on \n, render each line stacked.
    lines = text.split("\n")
    line_h = 36
    total = line_h * len(lines)
    y = (size[1] - total) // 2
    for line in lines:
        try:
            w = draw.textlength(line, font=font)
        except AttributeError:
            w = font.getsize(line)[0]
        x = (size[0] - w) // 2
        draw.text((x, y), line, fill="black", font=font)
        y += line_h
    return img


def blank_image_png(color: str = "white", size: tuple[int, int] = (200, 200)) -> Image.Image:
    return Image.new("RGB", size, color)


def main() -> int:
    print("[1] Generating image fixtures...")
    write_image(
        "image-with-email.png",
        text_image_png("Email: jane.doe@example.com"),
        "PNG",
    )
    write_image(
        "image-with-iban.png",
        text_image_png("IBAN:\nGB82 WEST 1234 5698 7654 32"),
        "PNG",
    )
    write_image(
        "image-with-card.png",
        text_image_png("Card 4242 4242 4242 4242"),
        "PNG",
    )
    write_image(
        "image-blank.png",
        blank_image_png(),
        "PNG",
    )
    # JPEG version of the email one to exercise CGImageSource's JPEG
    # decode path.
    write_image(
        "image-with-email.jpg",
        text_image_png("Email: jane.doe@example.com"),
        "JPEG",
    )
    print(f"\nDone — fixtures in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
