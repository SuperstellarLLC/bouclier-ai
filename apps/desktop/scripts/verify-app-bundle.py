#!/usr/bin/env python3
"""Fail when a packaged macOS app has missing resources or dylibraries."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


EXECUTABLES = ("Bouclier", "bouclier-ai-mcp-wrapper", "bouclier-cli")
SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")
COMPLIANCE_FILE_HASHES = {
    "LICENSE.txt": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "NOTICE.txt": "be9e00deca977c951650fa87a84490a001f2a3d5c840b91498eab3ec337e5d22",
    "LICENSES/Llama-4-Community-License.txt": "67a88a18344d9889b47c1880711264c4c7affa7194242d2821b8cfc2f4e0092c",
    "LICENSES/THIRD-PARTY-NOTICES.txt": "bbbb1411532ca24ed9e87b60c5608e84cdca80db15ac57350e2923e14fd6e6c5",
    "LICENSES/ThirdParty/GRDB.swift.txt": "9853f9dce81365fcc1d9b46004633354450164b8d17904e92e80c444545f7e87",
    "LICENSES/ThirdParty/Jinja.txt": "fb2e2daac54953cb820d24a607ac7beb6731dd6a3802bd5ae48fe466bc6a0030",
    "LICENSES/ThirdParty/Sparkle.txt": "389a4e4e9a32f059775b13a06e25a591445ba229d2838d26dd3e7c0c45127cfe",
    "LICENSES/ThirdParty/swift-atomics.txt": "770af8291f708538d8ff885a0bbc4e045cd700531741c4f99528d435c14d7f55",
    "LICENSES/ThirdParty/swift-collections.txt": "770af8291f708538d8ff885a0bbc4e045cd700531741c4f99528d435c14d7f55",
    "LICENSES/ThirdParty/swift-nio-NOTICE.txt": "d25ed2452b3476c342082d11e4e8bf5459174d2836124f842b499850bcebc50e",
    "LICENSES/ThirdParty/swift-nio-cpp_magic-uSHET.txt": "62a279b6a64b37680b691436c3ac1c0f6e8eeb81d8ad0a05c1dfc68f2c9ca28a",
    "LICENSES/ThirdParty/swift-nio-llhttp.txt": "ebca854e0134cd256d673627c20499f42577eb74bacf08b9f25b626a73c91277",
    "LICENSES/ThirdParty/swift-nio-ssl-BoringSSL.txt": "756a61a8300d105ae68e7f2993e27d41a765c946f3400422e2403b01e7ded527",
    "LICENSES/ThirdParty/swift-nio-ssl-NOTICE.txt": "03e8ca5c65a3df21fe1ab48eef91bca7d370db56c290d8ef16eaaa09ba322abe",
    "LICENSES/ThirdParty/swift-nio-ssl.txt": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "LICENSES/ThirdParty/swift-nio-transport-services.txt": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "LICENSES/ThirdParty/swift-nio.txt": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    "LICENSES/ThirdParty/swift-transformers.txt": "648b81e6c6f9975c3b6cf6d630229b6c8d6f1ddaef55f5770f576adda19f3495",
}
RUNTIME_SWIFTPM_PINS = {
    "grdb.swift": ("7.10.0", "36e30a6f1ef10e4194f6af0cff90888526f0c115"),
    "jinja": ("1.3.0", "5c0a87846dfd36ca6621795ad2f09fdaab82b739"),
    "sparkle": ("2.9.1", "066e75a8b3e99962685d6a90cdd5293ebffd9261"),
    "swift-atomics": ("1.3.0", "b601256eab081c0f92f059e12818ac1d4f178ff7"),
    "swift-collections": ("1.4.1", "6675bc0ff86e61436e615df6fc5174e043e57924"),
    "swift-nio": ("2.97.1", "558f24a4647193b5a0e2104031b71c55d31ff83a"),
    "swift-nio-ssl": ("2.36.1", "df9c3406028e3297246e6e7081977a167318b692"),
    "swift-nio-transport-services": ("1.26.0", "60c3e187154421171721c1a38e800b390680fb5d"),
    "swift-transformers": ("0.1.24", "f000aa7aec0e78acd0211685e4094e1fca84cd8b"),
}
NON_RUNTIME_SWIFTPM_PINS = {
    "swift-argument-parser": ("1.4.0", "0fbc8848e389af3bb55c182bc19ca9d5dc2f255b"),
    "swift-system": ("1.6.4", "7c6ad0fc39d0763e0b699210e4124afd5041c5df"),
    "viewinspector": ("0.10.3", "e9a06346499a3a889165647e3f23f8a7b2609a1c"),
}


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


def validate_compliance_assets(app: Path) -> list[str]:
    resources = app / "Contents" / "Resources"
    license_root = resources / "LICENSES"
    problems: list[str] = []

    required_directories = (
        app / "Contents",
        resources,
        license_root,
        license_root / "ThirdParty",
    )
    for directory in required_directories:
        if not directory.is_dir() or directory.is_symlink():
            problems.append(
                f"missing or symlinked compliance directory: {directory.relative_to(app)}"
            )

    for relative, expected_digest in COMPLIANCE_FILE_HASHES.items():
        path = resources / relative
        if not path.is_file() or path.is_symlink():
            problems.append(f"missing or symlinked compliance file: Contents/Resources/{relative}")
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            problems.append(f"unreadable compliance file: Contents/Resources/{relative}: {error}")
            continue
        if digest != expected_digest:
            problems.append(f"compliance checksum mismatch: Contents/Resources/{relative}")

    expected_license_files = {
        relative.removeprefix("LICENSES/")
        for relative in COMPLIANCE_FILE_HASHES
        if relative.startswith("LICENSES/")
    }
    if license_root.is_dir() and not license_root.is_symlink():
        actual_license_files: set[str] = set()
        for path in license_root.rglob("*"):
            relative = path.relative_to(license_root).as_posix()
            if path.is_symlink():
                problems.append(f"symlinked compliance asset: Contents/Resources/LICENSES/{relative}")
            elif path.is_file():
                actual_license_files.add(relative)
        for relative in sorted(actual_license_files - expected_license_files):
            problems.append(f"unexpected compliance file: Contents/Resources/LICENSES/{relative}")

    return problems


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

    problems.extend(validate_compliance_assets(app))

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
        help="require tokenizer and a compiled PromptGuard model",
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
