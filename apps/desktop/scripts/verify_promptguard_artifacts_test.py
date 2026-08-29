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
    def test_dependency_lock_contains_only_exact_unique_hash_locked_pins(self) -> None:
        lock_entries: list[str] = []
        continued = ""
        for line in (SCRIPT_DIR / "requirements-promptguard.lock").read_text(
            encoding="utf-8"
        ).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith("\\"):
                continued += stripped[:-1].rstrip() + " "
                continue
            lock_entries.append((continued + stripped).strip())
            continued = ""
        self.assertEqual(continued, "", "unterminated requirement continuation")

        exact_pin = re.compile(r"^([A-Za-z0-9_.-]+)==([^<>=!~\s]+)$")
        hash_option = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")
        matches = []
        for entry in lock_entries:
            pin, *hashes = entry.split()
            match = exact_pin.fullmatch(pin)
            self.assertIsNotNone(match, entry)
            self.assertTrue(hashes, f"dependency has no hashes: {pin}")
            self.assertTrue(all(hash_option.fullmatch(item) for item in hashes), entry)
            self.assertEqual(len(hashes), len(set(hashes)), entry)
            matches.append(match)

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
            "setuptools",
            "torch",
            "transformers",
        }
        self.assertTrue(required.issubset(normalized_names))

    def test_model_install_rejects_unhashed_or_source_dependencies(self) -> None:
        ensure_model = (SCRIPT_DIR / "ensure-model.sh").read_text(encoding="utf-8")

        self.assertIn("--require-hashes", ensure_model)
        self.assertIn("--only-binary=:all:", ensure_model)
        self.assertIn("--force-reinstall", ensure_model)
        self.assertIn("--no-deps", ensure_model)
        self.assertIn('rm -rf "$VENV"', ensure_model)
        self.assertIn('"$BASEPY" -I -m venv "$VENV"', ensure_model)
        self.assertIn("-m pip --isolated install", ensure_model)
        self.assertNotIn("needs_venv", ensure_model)
        self.assertLess(
            ensure_model.index('rm -rf "$VENV"'),
            ensure_model.index("-m pip --isolated install"),
        )

    def test_release_prepares_model_before_accessing_release_secrets(self) -> None:
        release = (SCRIPT_DIR / "release.sh").read_text(encoding="utf-8")
        model_preflight = release.index('"$SCRIPT_DIR/ensure-model.sh"')
        model_preflight_run = release.index("run_model_preflight ||")
        hf_cleanup = release.index("unset HF_TOKEN", model_preflight)
        remote_tag_check = release.index("ls-remote --exit-code --tags origin")
        build = release.index('"$SCRIPT_DIR/build-app.sh"')
        blob_prompt = release.index("prompt_secret BLOB_READ_WRITE_TOKEN")
        notary_submit = release.index("xcrun notarytool submit")

        self.assertLess(model_preflight, blob_prompt)
        self.assertLess(model_preflight, notary_submit)
        self.assertLess(remote_tag_check, model_preflight)
        self.assertLess(model_preflight, model_preflight_run)
        self.assertLess(model_preflight_run, hf_cleanup)
        self.assertLess(remote_tag_check, build)
        self.assertLess(hf_cleanup, build)
        self.assertLess(release.index("unset BLOB_READ_WRITE_TOKEN"), model_preflight)
        self.assertLess(release.index("unset HF_TOKEN"), remote_tag_check)
        self.assertLess(release.index("unset HUGGING_FACE_HUB_TOKEN"), remote_tag_check)
        self.assertGreaterEqual(release.count("unset HF_TOKEN"), 2)
        self.assertGreaterEqual(release.count("unset HUGGING_FACE_HUB_TOKEN"), 2)
        self.assertIn("export -n PRESET_BLOB_TOKEN", release)
        self.assertIn("export -n PRESET_HF_TOKEN", release)
        self.assertIn("export -n PRESET_HUGGING_FACE_HUB_TOKEN", release)
        self.assertIn('HF_TOKEN="$PRESET_HF_TOKEN"', release)
        self.assertIn(
            'HUGGING_FACE_HUB_TOKEN="$PRESET_HUGGING_FACE_HUB_TOKEN"', release
        )
        self.assertLess(
            release.index("unset PRESET_HF_TOKEN", model_preflight_run), build
        )
        self.assertNotIn("--password", release)
        self.assertIn("--keychain-profile", release)
        self.assertIn(
            'BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put',
            release,
        )
        self.assertNotIn('echo "    vercel blob put', release)

    def test_release_metadata_transaction_wraps_all_tracked_edits(self) -> None:
        release = (SCRIPT_DIR / "release.sh").read_text(encoding="utf-8")

        transaction_begin = release.index("release_transaction_begin")
        first_metadata_edit = release.index('sed -i \'\' "s/APP_VERSION')
        upload = release.index(
            'BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put'
        )
        transaction_commit = release.index("release_transaction_commit")

        self.assertLess(transaction_begin, first_metadata_edit)
        self.assertLess(upload, transaction_commit)
        self.assertIn("trap release_exit_handler EXIT", release)
        self.assertGreaterEqual(release.count("unset BLOB_READ_WRITE_TOKEN"), 4)

    def test_release_finalizes_outer_dmg_before_sparkle_and_metadata_commit(
        self,
    ) -> None:
        release = (SCRIPT_DIR / "release.sh").read_text(encoding="utf-8")
        ordered_markers = [
            "hdiutil create",
            'codesign --force --timestamp --sign "$SIGNING_IDENTITY" "$DMG"',
            'submit_for_notarization "$DMG"',
            'xcrun stapler staple -v "$DMG"',
            'xcrun stapler validate -v "$DMG"',
            'spctl --assess --type open --context context:primary-signature -vv "$DMG"',
            '"$SCRIPT_DIR/publish-update.sh"',
            'BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put',
            'verify_public_file "$PUBLIC_URL" "$DMG"',
            "release_transaction_commit",
        ]
        positions = [release.index(marker) for marker in ordered_markers]

        self.assertEqual(positions, sorted(positions))
        self.assertEqual(
            release.count('codesign --verify --strict --verbose=2 "$DMG"'), 2
        )
        self.assertIn("RELEASE_PIPELINE=1", release)
        self.assertNotIn("APP_ZIP", release)
        self.assertIn(
            '! semver_greater_than "$VERSION" "$RELEASED_VERSION"', release
        )
        self.assertIn('show-ref --verify --quiet "refs/tags/v${VERSION}"', release)
        self.assertIn(
            'ls-remote --exit-code --tags origin \\\n  "refs/tags/v${VERSION}"',
            release,
        )
        self.assertIn('case "$remote_tag_status" in', release)
        self.assertIn("  2) ;;", release)
        branch_gate = release.index(
            'symbolic-ref --quiet --short HEAD'
        )
        baseline_refresh = release.index(
            'ORIGIN_MAIN_COMMIT=$(refresh_origin_main)'
        )
        baseline_capture = release.index(
            'RELEASE_BASE_COMMIT=$(git -C "$REPO_ROOT" rev-parse \'HEAD^{commit}\')'
        )
        race_refresh = release.index(
            'LATEST_ORIGIN_MAIN_COMMIT=$(refresh_origin_main)'
        )
        self.assertLess(branch_gate, baseline_refresh)
        self.assertLess(baseline_refresh, baseline_capture)
        self.assertLess(baseline_capture, release.index("run_model_preflight ||"))
        self.assertLess(positions[6], race_refresh)
        self.assertLess(race_refresh, positions[7])
        self.assertEqual(release.count("$(refresh_origin_main)"), 2)
        self.assertIn(
            'fetch --quiet --no-tags origin main', release
        )
        self.assertIn(
            '[ "$RELEASE_BASE_COMMIT" != "$ORIGIN_MAIN_COMMIT" ]', release
        )
        self.assertIn(
            '[ "$LATEST_ORIGIN_MAIN_COMMIT" != "$RELEASE_BASE_COMMIT" ]',
            release,
        )
        self.assertIn('echo "    git push origin main"', release)
        self.assertNotIn('git push origin HEAD', release)
        first_metadata_edit = release.index('sed -i \'\' "s/APP_VERSION')
        verified_rewrite = release.index("\nverify_source_versions\n", first_metadata_edit)
        self.assertLess(verified_rewrite, positions[0])

    def test_standalone_release_utilities_scope_credentials_and_validate_output(
        self,
    ) -> None:
        upload = (SCRIPT_DIR / "upload-dmg.sh").read_text(encoding="utf-8")
        publish = (SCRIPT_DIR / "publish-update.sh").read_text(encoding="utf-8")

        for credential in (
            "BLOB_READ_WRITE_TOKEN",
            "HF_TOKEN",
            "HUGGING_FACE_HUB_TOKEN",
            "APP_PASSWORD",
        ):
            self.assertIn(f"unset {credential}", upload)
            self.assertIn(f"unset {credential}", publish)

        upload_command = upload.index(
            'BLOB_READ_WRITE_TOKEN="$BLOB_READ_WRITE_TOKEN" vercel blob put'
        )
        public_verification = upload.index(
            'verify_public_file "$PUBLIC_URL" "$DMG"'
        )
        self.assertLess(upload.index("xcrun stapler validate"), upload_command)
        self.assertLess(upload_command, public_verification)
        self.assertIn('codesign --verify --strict --verbose=2 "$DMG"', upload)
        self.assertIn("Artifact-only recovery complete", upload)
        self.assertIn(
            '! semver_greater_than "$VERSION" "$RELEASED_VERSION"', upload
        )
        self.assertIn(
            'ls-remote --exit-code --tags origin \\\n  "refs/tags/v${VERSION}"',
            upload,
        )
        self.assertIn('case "$remote_tag_status" in', upload)

        signature_validation = publish.index(
            '[[ "$ED_SIG" =~ ^[A-Za-z0-9+/]{86}==$ ]]'
        )
        length_validation = publish.index('[ "$LENGTH" != "$DMG_SIZE" ]')
        temporary_appcast = publish.index('APPCAST_TMP=$(mktemp')
        xml_validation = publish.index('xmllint --noout "$APPCAST_TMP"')
        atomic_replace = publish.index('mv "$APPCAST_TMP" "$APPCAST_OUT"')
        self.assertLess(signature_validation, length_validation)
        self.assertLess(length_validation, temporary_appcast)
        self.assertLess(temporary_appcast, xml_validation)
        self.assertLess(xml_validation, atomic_replace)
        self.assertIn('DECODED_SIGNATURE_SIZE" != "64"', publish)
        self.assertIn('${RELEASE_PIPELINE:-}', publish)
        self.assertIn('codesign --verify --strict --verbose=2 "$DMG"', publish)

    def test_converter_and_checksum_manifest_pin_reviewed_revision(self) -> None:
        converter = (SCRIPT_DIR / "convert-promptguard.py").read_text(encoding="utf-8")
        checksums = (SCRIPT_DIR / "promptguard-artifacts.sha256").read_text(
            encoding="utf-8"
        )

        self.assertIn(f'MODEL_REVISION = "{PINNED_REVISION}"', converter)
        self.assertEqual(converter.count("revision=MODEL_REVISION"), 4)
        self.assertIn(PINNED_REVISION, checksums)


class ReleaseTransactionTests(unittest.TestCase):
    def test_failed_transaction_restores_existing_and_absent_files(self) -> None:
        helper = SCRIPT_DIR / "_release_transaction.sh"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            existing = root / "constants.ts"
            originally_absent = root / "appcast.xml"
            existing.write_bytes(b"original bytes\n")

            script = r"""
set -euo pipefail
helper="$1"
existing="$2"
originally_absent="$3"
source "$helper"
release_transaction_begin "$existing" "$originally_absent"
finish_transaction() {
  status=$?
  trap - EXIT
  release_transaction_finish "$status"
  exit $?
}
trap finish_transaction EXIT
printf 'changed\n' > "$existing"
printf 'new appcast\n' > "$originally_absent"
exit 23
"""
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    script,
                    "transaction-test",
                    str(helper),
                    str(existing),
                    str(originally_absent),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(existing.read_bytes(), b"original bytes\n")
            self.assertFalse(originally_absent.exists())
            self.assertIn("Restoring tracked release metadata", result.stderr)

    def test_committed_transaction_keeps_metadata_edits(self) -> None:
        helper = SCRIPT_DIR / "_release_transaction.sh"
        with tempfile.TemporaryDirectory() as temporary_directory:
            metadata = Path(temporary_directory) / "constants.ts"
            metadata.write_text("original\n", encoding="utf-8")
            script = r"""
set -euo pipefail
source "$1"
release_transaction_begin "$2"
printf 'released\n' > "$2"
release_transaction_commit
release_transaction_finish 0
"""
            result = subprocess.run(
                ["bash", "-c", script, "transaction-test", str(helper), str(metadata)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(metadata.read_text(encoding="utf-8"), "released\n")


if __name__ == "__main__":
    unittest.main()
