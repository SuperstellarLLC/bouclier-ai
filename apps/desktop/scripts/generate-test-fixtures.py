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


def text_pdf(text: str, name: str) -> None:
    """Generate a text-layer PDF via reportlab. PDFKit's text-layer
    extraction reads these natively without OCR."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as _canvas
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    c = _canvas.Canvas(str(path), pagesize=letter)
    c.setFont("Helvetica", 14)
    y = 720
    for line in text.split("\n"):
        c.drawString(72, y, line)
        y -= 22
    c.showPage()
    c.save()
    print(f"  → {name} ({path.stat().st_size:,} bytes)")


def audio_fixtures() -> None:
    """Generate short MP3 audio fixtures via macOS's built-in `say`.
    The Swift AudioPIIScanner tests don't actually exercise these (the
    Speech-framework recogniser isn't reliably authorised in headless
    test environments — tests inject a stub transcriber instead) but
    they're useful for manual reproduction and stay tiny (<50 KB)."""
    import subprocess, shutil
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not shutil.which("say"):
        print("  ! `say` not available (non-macOS environment); skipping audio fixtures")
        return
    samples = [
        ("audio-with-email.m4a", "My email is alice at example dot com"),
        ("audio-clean.m4a", "The weather today is partly cloudy"),
    ]
    for name, phrase in samples:
        path = OUT_DIR / name
        # Direct AAC output via the say --data-format flag. Keeps the
        # file small (~5-10 KB per second) and gives us a real audio
        # container Apple can decode.
        subprocess.run([
            "say", "--voice=Samantha", "--rate=180",
            "--data-format=aac",
            "-o", str(path),
            phrase,
        ], check=False)
        if path.exists():
            print(f"  → {name} ({path.stat().st_size:,} bytes)")


def encrypted_pdf(text: str, name: str, password: str = "hunter2") -> None:
    """Generate a password-protected PDF. reportlab uses the same
    canvas API + the StandardEncryption helper."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as _canvas
    from reportlab.lib.pdfencrypt import StandardEncryption
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    enc = StandardEncryption(userPassword=password, ownerPassword=password,
                             canPrint=0, canModify=0, canCopy=0, canAnnotate=0)
    c = _canvas.Canvas(str(path), pagesize=letter, encrypt=enc)
    c.setFont("Helvetica", 14)
    y = 720
    for line in text.split("\n"):
        c.drawString(72, y, line)
        y -= 22
    c.showPage()
    c.save()
    print(f"  → {name} ({path.stat().st_size:,} bytes, encrypted)")


def scanned_pdf(text: str, name: str, pages: int = 1) -> None:
    """Generate a scanned-style PDF — one rasterised image per page
    with no embedded text layer. Forces Vision OCR fallback on read."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas as _canvas
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    c = _canvas.Canvas(str(path), pagesize=letter)
    for page in range(pages):
        img = text_image_png(text if pages == 1 else f"Page {page+1}\n{text}", size=(800, 1000))
        import io
        buf = io.BytesIO()
        img.save(buf, "PNG")
        buf.seek(0)
        c.drawImage(ImageReader(buf), 50, 50, width=512, height=640)
        c.showPage()
    c.save()
    print(f"  → {name} ({path.stat().st_size:,} bytes)")


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

    print("\n[2] Generating audio fixtures via macOS `say` (synthesised speech)...")
    audio_fixtures()
    print("\n[3] Generating PDF fixtures...")
    text_pdf("Invoice for Acme Co.\nContact: alice@acme.io\nIBAN GB82 WEST 1234 5698 7654 32",
             "pdf-text-with-pii.pdf")
    text_pdf("Just a meeting agenda\nWelcome\nAgenda items\nClosing", "pdf-text-clean.pdf")
    scanned_pdf("Email: bob@example.com\nCard 4242 4242 4242 4242", "pdf-scanned-with-pii.pdf")
    # Encrypted PDF exercises the unscannable.encrypted P0 fix:
    # the proxy must still strip the document even though we can't
    # read its contents.
    encrypted_pdf(
        "Confidential — Email: alice@example.com\nIBAN GB82 WEST 1234 5698 7654 32",
        "pdf-encrypted.pdf",
        password="hunter2"
    )
    print(f"\nDone — fixtures in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
