#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-promptguard-artifacts.py")
SCRIPT_DIR = SCRIPT.parent
PINNED_REVISION = "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"


class PromptGuardArtifactVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.resources = self.root / "Resources"
        self.model_file = (
            self.resources
            / "PromptGuard2.mlpackage"
            / "Data"
            / "com.apple.CoreML"
            / "model.mlmodel"
        )
        self.tokenizer_file = self.resources / "PromptGuardTokenizer" / "tokenizer.json"
        self.model_file.parent.mkdir(parents=True)
        self.tokenizer_file.parent.mkdir(parents=True)
        self.model_file.write_bytes(b"reviewed model")
        self.tokenizer_file.write_bytes(b"reviewed tokenizer")
        self.manifest = self.root / "artifacts.sha256"
        self.write_manifest()

    def write_manifest(self) -> None:
        entries = []
        for path in (self.model_file, self.tokenizer_file):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            relative = path.relative_to(self.resources).as_posix()
            entries.append(f"{digest}  {relative}")
        self.manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--resources-dir",
                str(self.resources),
                "--manifest",
                str(self.manifest),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_exact_files_and_ignores_cache_metadata(self) -> None:
        cache_file = self.resources / "PromptGuardTokenizer" / ".cache" / "metadata"
        cache_file.parent.mkdir()
        cache_file.write_text("transport metadata", encoding="utf-8")

        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unexpected_non_cache_file(self) -> None:
        (self.resources / "PromptGuardTokenizer" / "unreviewed.json").write_text(
            "{}",
            encoding="utf-8",
        )

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected: PromptGuardTokenizer/unreviewed.json", result.stderr)

    def test_rejects_changed_file(self) -> None:
        self.model_file.write_bytes(b"tampered model")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hash mismatch", result.stderr)

    def test_rejects_manifest_path_traversal(self) -> None:
        digest = hashlib.sha256(b"anything").hexdigest()
        self.manifest.write_text(f"{digest}  ../outside\n", encoding="utf-8")

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe or out-of-scope path", result.stderr)

    def test_rejects_symlinked_artifact_root(self) -> None:
        model_root = self.resources / "PromptGuard2.mlpackage"
        real_model = self.root / "real-model"
        model_root.rename(real_model)
        model_root.symlink_to(real_model, target_is_directory=True)

        result = self.run_verifier()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink is not allowed: PromptGuard2.mlpackage", result.stderr)


class PromptGuardSupplyChainMetadataTests(unittest.TestCase):
    def test_dependency_lock_contains_only_exact_unique_pins(self) -> None:
        lock_lines = [
            line.strip()
            for line in (SCRIPT_DIR / "requirements-promptguard.lock")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        exact_pin = re.compile(r"^([A-Za-z0-9_.-]+)==([^<>=!~\s]+)$")
        matches = [exact_pin.fullmatch(line) for line in lock_lines]
        self.assertTrue(all(matches), lock_lines)

        normalized_names = [
            match.group(1).lower().replace("_", "-")
            for match in matches
            if match is not None
        ]
        self.assertEqual(len(normalized_names), len(set(normalized_names)))
        required = {
            "coremltools",
            "huggingface-hub",
            "onnx",
            "onnxruntime",
            "protobuf",
            "sentencepiece",
            "torch",
            "transformers",
        }
        self.assertTrue(required.issubset(normalized_names))

    def test_converter_and_checksum_manifest_pin_reviewed_revision(self) -> None:
        converter = (SCRIPT_DIR / "convert-promptguard.py").read_text(encoding="utf-8")
        checksums = (SCRIPT_DIR / "promptguard-artifacts.sha256").read_text(
            encoding="utf-8"
        )

        self.assertIn(f'MODEL_REVISION = "{PINNED_REVISION}"', converter)
        self.assertEqual(converter.count("revision=MODEL_REVISION"), 4)
        self.assertIn(PINNED_REVISION, checksums)


if __name__ == "__main__":
    unittest.main()
