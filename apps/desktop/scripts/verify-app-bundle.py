#!/usr/bin/env python3
"""Fail when a packaged macOS app has missing resources or dylibraries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


EXECUTABLES = ("Bouclier", "bouclier-ai-mcp-wrapper", "bouclier-cli")
SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")


def otool(*arguments: str) -> str:
    completed = subprocess.run(
        ["otool", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "otool failed")
    return completed.stdout


def linked_libraries(binary: Path) -> list[str]:
    lines = otool("-L", str(binary)).splitlines()[1:]
    return [line.strip().split(" (", 1)[0] for line in lines if line.strip()]


def rpaths(binary: Path) -> list[str]:
    lines = otool("-l", str(binary)).splitlines()
    values: list[str] = []
    waiting_for_path = False
    for line in lines:
        fields = line.strip().split()
        if len(fields) == 2 and fields[0] == "cmd":
            waiting_for_path = fields[1] == "LC_RPATH"
        elif waiting_for_path and len(fields) >= 2 and fields[0] == "path":
            values.append(fields[1])
            waiting_for_path = False
    return values


def is_system_path(value: str) -> bool:
    return value.startswith(SYSTEM_PREFIXES)


def is_inside(path: Path, app: Path) -> bool:
    try:
        path.resolve().relative_to(app.resolve())
        return True
    except (OSError, ValueError):
        return False


def expand_anchored(value: str, binary: Path) -> Optional[Path]:
    anchors = {
        "@executable_path": binary.parent,
        "@loader_path": binary.parent,
    }
    for marker, base in anchors.items():
        if value == marker:
            return base
        prefix = marker + "/"
        if value.startswith(prefix):
            return base / value[len(prefix) :]
    return None


def validate_rpaths(binary: Path, app: Path) -> tuple[list[str], list[str]]:
    values = rpaths(binary)
    problems: list[str] = []
    for value in values:
        if is_system_path(value):
            continue
        expanded = expand_anchored(value, binary)
        if expanded is None or not is_inside(expanded, app) or not expanded.exists():
            problems.append(f"{binary.name}: non-portable rpath {value}")
    return values, problems


def resolves_rpath_dependency(
    dependency: str,
    binary: Path,
    app: Path,
    binary_rpaths: list[str],
) -> bool:
    suffix = dependency.removeprefix("@rpath/")
    for value in binary_rpaths:
        if is_system_path(value):
            candidate = Path(value) / suffix
            # Modern macOS keeps many Swift compatibility libraries only in
            # the dyld shared cache. Their filesystem symlinks can therefore
            # appear dangling even though dyld resolves them from this system
            # rpath. Restrict that exception to flat libswift dylib names so a
            # missing bundled framework can never pass as a system library.
            is_shared_cache_swift_library = (
                "/" not in suffix
                and suffix.startswith("libswift")
                and suffix.endswith(".dylib")
            )
            if candidate.exists() or is_shared_cache_swift_library:
                return True
            continue
        expanded = expand_anchored(value, binary)
        if expanded is None:
            continue
        candidate = expanded / suffix
        if is_inside(candidate, app) and candidate.exists():
            return True
    return False


def validate_dependency(
    dependency: str,
    binary: Path,
    app: Path,
    binary_rpaths: list[str],
) -> Optional[str]:
    if is_system_path(dependency):
        return None
    if dependency.startswith("@rpath/"):
        if resolves_rpath_dependency(dependency, binary, app, binary_rpaths):
            return None
        return f"{binary.name}: unresolved dependency {dependency}"

    expanded = expand_anchored(dependency, binary)
    if expanded is not None and is_inside(expanded, app) and expanded.exists():
        return None

    dependency_path = Path(dependency)
    if dependency_path.is_absolute() and is_inside(dependency_path, app) and dependency_path.exists():
        return None
    return f"{binary.name}: external or unresolved dependency {dependency}"


def validate_promptguard(
    app: Path,
    allow_raw_promptguard: bool,
) -> list[str]:
    resources = (
        app
        / "Contents"
        / "Resources"
        / "Bouclier_Bouclier.bundle"
        / "Resources"
    )
    compiled = resources / "PromptGuard2.mlmodelc"
    raw = resources / "PromptGuard2.mlpackage"
    tokenizer = resources / "PromptGuardTokenizer"
    problems: list[str] = []

    required_runtime_files = (
        tokenizer / "config.json",
        tokenizer / "special_tokens_map.json",
        tokenizer / "tokenizer.json",
        tokenizer / "tokenizer_config.json",
        app / "Contents" / "Resources" / "NOTICE.txt",
        app
        / "Contents"
        / "Resources"
        / "LICENSES"
        / "Llama-4-Community-License.txt",
    )
    for path in required_runtime_files:
        if not path.is_file() or path.is_symlink():
            problems.append(f"missing PromptGuard runtime file: {path.relative_to(app)}")

    if compiled.is_dir() and not compiled.is_symlink():
        required_compiled_files = (
            compiled / "coremldata.bin",
            compiled / "metadata.json",
            compiled / "model.mil",
            compiled / "weights" / "weight.bin",
        )
        for path in required_compiled_files:
            if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
                problems.append(f"invalid compiled PromptGuard file: {path.relative_to(app)}")
        metadata_path = compiled / "metadata.json"
        if metadata_path.is_file() and not metadata_path.is_symlink():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                record = metadata[0]
                input_names = {item["name"] for item in record["inputSchema"]}
                output_names = {item["name"] for item in record["outputSchema"]}
                if input_names != {"input_ids", "attention_mask"} or "logits" not in output_names:
                    problems.append("compiled PromptGuard metadata has an unexpected schema")
            except (IndexError, KeyError, OSError, TypeError, json.JSONDecodeError):
                problems.append("compiled PromptGuard metadata is malformed")
        if raw.exists() or raw.is_symlink():
            problems.append("raw PromptGuard2.mlpackage remained beside compiled model")
        return problems

    if not allow_raw_promptguard:
        problems.append("compiled PromptGuard2.mlmodelc is missing")
        return problems

    required_raw_files = (
        raw / "Manifest.json",
        raw / "Data" / "com.apple.CoreML" / "model.mlmodel",
        raw / "Data" / "com.apple.CoreML" / "weights" / "weight.bin",
    )
    if not raw.is_dir() or raw.is_symlink():
        problems.append("raw PromptGuard fallback is missing or symlinked")
        return problems
    for path in required_raw_files:
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            problems.append(f"invalid raw PromptGuard file: {path.relative_to(app)}")
    return problems


def verify(
    app: Path,
    require_promptguard: bool = False,
    allow_raw_promptguard: bool = False,
) -> list[str]:
    problems: list[str] = []
    required_paths = (
        app / "Contents" / "Resources" / "Bouclier_Bouclier.bundle" / "Resources" / "patterns.json",
        app / "Contents" / "Frameworks" / "Sparkle.framework" / "Versions" / "B" / "Sparkle",
        app / "Contents" / "Info.plist",
    )
    for path in required_paths:
        if not path.exists():
            problems.append(f"missing packaged file: {path.relative_to(app)}")

    cache_directories = sorted(
        path.relative_to(app).as_posix()
        for path in app.rglob(".cache")
        if path.is_dir() or path.is_symlink()
    )
    for relative in cache_directories:
        problems.append(f"cache directory was packaged: {relative}")

    if require_promptguard:
        problems.extend(validate_promptguard(app, allow_raw_promptguard))

    for name in EXECUTABLES:
        binary = app / "Contents" / "MacOS" / name
        if not binary.is_file():
            problems.append(f"missing packaged executable: Contents/MacOS/{name}")
            continue
        try:
            binary_rpaths, rpath_problems = validate_rpaths(binary, app)
            problems.extend(rpath_problems)
            for dependency in linked_libraries(binary):
                problem = validate_dependency(dependency, binary, app, binary_rpaths)
                if problem is not None:
                    problems.append(problem)
        except RuntimeError as error:
            problems.append(f"{name}: {error}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument(
        "--require-promptguard",
        action="store_true",
        help="require tokenizer, notices, and a compiled PromptGuard model",
    )
    parser.add_argument(
        "--allow-raw-promptguard",
        action="store_true",
        help="allow verified raw model fallback when coremlcompiler was unavailable",
    )
    args = parser.parse_args()
    if args.allow_raw_promptguard and not args.require_promptguard:
        parser.error("--allow-raw-promptguard requires --require-promptguard")
    app = args.app.resolve()

    if not app.is_dir():
        print(f"ERROR: app bundle not found: {app}", file=sys.stderr)
        return 1
    problems = verify(
        app,
        require_promptguard=args.require_promptguard,
        allow_raw_promptguard=args.allow_raw_promptguard,
    )
    if problems:
        print("ERROR: packaged app verification failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("  ✓ Packaged resources and Mach-O dependencies verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
