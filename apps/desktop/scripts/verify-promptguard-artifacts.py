#!/usr/bin/env python3
"""Verify the exact reviewed PromptGuard model and tokenizer file set."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RESOURCES_DIR = SCRIPT_DIR.parent / "Sources" / "Bouclier" / "Resources"
DEFAULT_MANIFEST = SCRIPT_DIR / "promptguard-artifacts.sha256"
ARTIFACT_ROOTS = ("PromptGuard2.mlpackage", "PromptGuardTokenizer")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    """A malformed manifest or an unreviewed artifact surface."""


def load_manifest(path: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise VerificationError(f"{path}:{line_number}: malformed checksum line")
        digest, relative_text = parts
        relative = PurePosixPath(relative_text.strip())
        if not SHA256_RE.fullmatch(digest):
            raise VerificationError(f"{path}:{line_number}: invalid SHA-256")
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or ".cache" in relative.parts
            or not relative.parts
            or relative.parts[0] not in ARTIFACT_ROOTS
        ):
            raise VerificationError(
                f"{path}:{line_number}: unsafe or out-of-scope path {relative}"
            )
        relative_string = relative.as_posix()
        if relative_string in expected:
            raise VerificationError(
                f"{path}:{line_number}: duplicate path {relative_string}"
            )
        expected[relative_string] = digest

    if not expected:
        raise VerificationError(f"{path}: checksum manifest is empty")
    return expected


def artifact_files(resources_dir: Path) -> tuple[set[str], list[str]]:
    files: set[str] = set()
    symlinks: list[str] = []
    for root_name in ARTIFACT_ROOTS:
        root = resources_dir / root_name
        if not root.exists() and not root.is_symlink():
            continue
        if root.is_symlink():
            symlinks.append(root_name)
            continue
        for candidate in root.rglob("*"):
            relative = candidate.relative_to(resources_dir)
            if ".cache" in relative.parts:
                continue
            relative_string = relative.as_posix()
            if candidate.is_symlink():
                symlinks.append(relative_string)
            elif candidate.is_file():
                files.add(relative_string)
    return files, sorted(symlinks)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(resources_dir: Path, manifest_path: Path) -> list[str]:
    expected = load_manifest(manifest_path)
    actual, symlinks = artifact_files(resources_dir)
    expected_paths = set(expected)
    problems: list[str] = []

    for relative in sorted(expected_paths - actual):
        problems.append(f"missing: {relative}")
    for relative in sorted(actual - expected_paths):
        problems.append(f"unexpected: {relative}")
    for relative in symlinks:
        problems.append(f"symlink is not allowed: {relative}")

    for relative in sorted(expected_paths & actual):
        observed = sha256(resources_dir / relative)
        if observed != expected[relative]:
            problems.append(
                f"hash mismatch: {relative} (expected {expected[relative]}, got {observed})"
            )
    return problems


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--resources-dir",
        type=Path,
        default=DEFAULT_RESOURCES_DIR,
        help="directory containing PromptGuard2.mlpackage and PromptGuardTokenizer",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="reviewed SHA-256 manifest",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        problems = verify(args.resources_dir.resolve(), args.manifest.resolve())
    except (OSError, VerificationError) as error:
        print(f"ERROR: PromptGuard verification could not run: {error}", file=sys.stderr)
        return 1

    if problems:
        print("ERROR: PromptGuard artifacts do not match the reviewed release:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("  ✓ PromptGuard model and tokenizer match the reviewed SHA-256 manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
