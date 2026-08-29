#!/usr/bin/env python3
"""Focused tests for deterministic app-bundle compliance assets."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("verify-app-bundle.py")
SPEC = importlib.util.spec_from_file_location("verify_app_bundle", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
REPO_ROOT = Path(__file__).resolve().parents[3]


class ComplianceAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.app = Path(self.temporary_directory.name) / "Bouclier-ai.app"
        self.resources = self.app / "Contents" / "Resources"
        self.resources.mkdir(parents=True)

        for relative in VERIFIER.COMPLIANCE_FILE_HASHES:
            source_relative = "LICENSE" if relative == "LICENSE.txt" else relative
            source = REPO_ROOT / source_relative
            destination = self.resources / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)

    def test_reviewed_source_set_is_valid(self) -> None:
        self.assertEqual(VERIFIER.validate_compliance_assets(self.app), [])

    def test_resolved_dependency_graph_matches_reviewed_inventory(self) -> None:
        package_resolved = REPO_ROOT / "apps" / "desktop" / "Package.resolved"
        document = json.loads(package_resolved.read_text(encoding="utf-8"))
        actual_pins = {
            pin["identity"]: (pin["state"]["version"], pin["state"]["revision"])
            for pin in document["pins"]
        }
        expected_pins = {
            **VERIFIER.RUNTIME_SWIFTPM_PINS,
            **VERIFIER.NON_RUNTIME_SWIFTPM_PINS,
        }
        self.assertEqual(actual_pins, expected_pins)

        inventory = (REPO_ROOT / "LICENSES" / "THIRD-PARTY-NOTICES.txt").read_text(
            encoding="utf-8"
        )
        for version, revision in VERIFIER.RUNTIME_SWIFTPM_PINS.values():
            self.assertIn(version, inventory)
            self.assertIn(revision, inventory)

    def test_missing_file_is_rejected(self) -> None:
        missing = self.resources / "LICENSES" / "ThirdParty" / "Sparkle.txt"
        missing.unlink()
        problems = VERIFIER.validate_compliance_assets(self.app)
        self.assertTrue(any("missing or symlinked compliance file" in item for item in problems))

    def test_modified_file_is_rejected(self) -> None:
        modified = self.resources / "NOTICE.txt"
        modified.write_text("changed\n", encoding="utf-8")
        problems = VERIFIER.validate_compliance_assets(self.app)
        self.assertIn(
            "compliance checksum mismatch: Contents/Resources/NOTICE.txt",
            problems,
        )

    def test_unreviewed_license_file_is_rejected(self) -> None:
        extra = self.resources / "LICENSES" / "unreviewed.txt"
        extra.write_text("not reviewed\n", encoding="utf-8")
        problems = VERIFIER.validate_compliance_assets(self.app)
        self.assertIn(
            "unexpected compliance file: Contents/Resources/LICENSES/unreviewed.txt",
            problems,
        )

    def test_symlinked_resources_ancestor_is_rejected(self) -> None:
        external_resources = Path(self.temporary_directory.name) / "external-resources"
        self.resources.rename(external_resources)
        self.resources.symlink_to(external_resources, target_is_directory=True)

        problems = VERIFIER.validate_compliance_assets(self.app)
        self.assertIn(
            "missing or symlinked compliance directory: Contents/Resources",
            problems,
        )


if __name__ == "__main__":
    unittest.main()
