import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "qualification" / "test_split_archive_finalization_windows.ps1"


class WindowsSplitFinalizationHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HARNESS.read_text(encoding="utf-8")

    def test_invokes_nscb_twice_and_checks_each_cli_result(self):
        self.assertIsNotNone(
            re.search(r"(?im)^\s*\[string\]\$NscbExecutable\s*$", self.source),
            "the executable path must be an explicit harness input",
        )
        self.assertIsNotNone(
            re.search(
                r"(?i)&\s+\$nscbExecutable\s+'finalize-split-set'\s+\$target\s+'--json'",
                self.source,
            ),
            "the harness must call NSCB's finalization command",
        )
        self.assertIn("$LASTEXITCODE", self.source)
        self.assertIsNotNone(
            re.search(r"(?i)if\s*\(\$exitCode\s*-ne\s*0\)", self.source),
            "each invocation must reject a nonzero exit code",
        )
        self.assertIn("ConvertFrom-Json", self.source)
        self.assertIsNotNone(
            re.search(
                r"(?i)\$firstResult\.result\.archive_attribute\s*-ne\s*'set'",
                self.source,
            ),
            "the first call must report archive_attribute=set",
        )
        self.assertIsNotNone(
            re.search(
                r"(?i)\$secondResult\.result\.archive_attribute\s*-ne\s*'already_set'",
                self.source,
            ),
            "the second call must report archive_attribute=already_set",
        )
        self.assertIsNotNone(
            re.search(r"(?im)^\s*\$firstResult\s*=\s*Invoke-NscbFinalizer\b", self.source),
            "the first finalizer invocation must be explicit",
        )
        self.assertIsNotNone(
            re.search(
                r"(?im)^\s*\$secondResult\s*=\s*Invoke-NscbFinalizer\b", self.source
            ),
            "the second finalizer invocation must be explicit",
        )

    def test_reads_attributes_independently_and_never_sets_them_directly(self):
        self.assertIn("EntryPoint = \"GetFileAttributesW\"", self.source)
        self.assertNotIn("SetFileAttributesW", self.source)
        self.assertNotIn("Set-AttributeMask", self.source)
        self.assertRegex(self.source, r"(?im)^\s*\[uint32\]\$afterFirst\s*=\s*Get-AttributeMask\s+\$target")
        self.assertRegex(self.source, r"(?im)^\s*\[uint32\]\$afterSecond\s*=\s*Get-AttributeMask\s+\$target")
        self.assertIn("($afterFirst -band $nonArchiveMask) -eq ($before -band $nonArchiveMask)", self.source)
        self.assertIn("($afterSecond -band $nonArchiveMask) -eq ($before -band $nonArchiveMask)", self.source)

    def test_checks_sentinel_content_hash_and_attributes(self):
        self.assertIn("sentinelHashBefore = (Get-FileHash", self.source)
        self.assertIn("sentinelHashAfter = (Get-FileHash", self.source)
        self.assertIn("sentinelFileLengthBefore", self.source)
        self.assertIn("sentinelFileLengthAfter", self.source)
        self.assertIn("$sentinelFileLengthAfter -ne $sentinelFileLengthBefore", self.source)
        self.assertIn("$sentinelFileMaskAfter -eq $sentinelFileMaskBefore", self.source)
        self.assertIn(
            "$sentinelDirectoryMaskAfter -eq $sentinelDirectoryMaskBefore", self.source
        )
        self.assertIn("$sentinelHashAfter -eq $sentinelHashBefore", self.source)

    def test_uses_isolated_state_and_checks_no_trust_receipt_store(self):
        self.assertIn("NSCB_STATE_DIR", self.source)
        self.assertIn("'split-trust'", self.source)
        self.assertRegex(
            self.source,
            r"(?is)if\s*\(Test-Path\s+-LiteralPath\s+\$trustStoreDirectory\).*?throw",
        )

    def test_keeps_receipt_completeness_and_interoperability_unestablished(self):
        self.assertIn("source_backed_completeness -ne 'not_established'", self.source)
        self.assertIn("consumer_interoperability -ne 'not_established'", self.source)
        self.assertIn("Properties['trust_receipt']", self.source)

    def test_reports_the_executable_identity_used_for_finalization(self):
        self.assertIn(
            "$nscbExecutableSha256 = (Get-FileHash -LiteralPath $nscbExecutable -Algorithm SHA256).Hash",
            self.source,
        )
        self.assertIn("nscb_executable_path = $nscbExecutable", self.source)
        self.assertIn("nscb_executable_sha256 = $nscbExecutableSha256", self.source)

    def test_checks_the_unrelated_sentinel_directory_contents(self):
        self.assertGreaterEqual(
            self.source.count("Get-ChildItem -LiteralPath $sentinelDirectory -Force"),
            2,
        )
        self.assertIn("sentinel_directory_entries_unchanged", self.source)


if __name__ == "__main__":
    unittest.main()
