"""Fail-closed artifact and diagnostic protocol regressions."""
import unittest

from build import IMAGE_BYTES, inspect_image, inspect_sector
from smoke import BOOT, EXPECTED, check_trace


class ArtifactAndProtocolTests(unittest.TestCase):
    def test_rejects_bad_boot_signature_and_truncated_sector(self) -> None:
        valid = bytes(510) + b"\x55\xaa"
        inspect_sector(valid)
        for corrupt in (valid[:-1], valid[:-2] + b"\x00\x00", valid + b"\x00"):
            with self.assertRaises(ValueError):
                inspect_sector(corrupt)

    def test_rejects_missing_extra_or_nonzero_payload(self) -> None:
        valid = bytes(510) + b"\x55\xaa" + bytes(IMAGE_BYTES - 512)
        inspect_image(valid)
        for corrupt in (valid[:-1], valid + b"\x00", valid[:-1] + b"\x01"):
            with self.assertRaises(ValueError):
                inspect_image(corrupt)

    def test_rejects_false_success_or_fault_without_boot(self) -> None:
        for variant, marker in EXPECTED.items():
            check_trace(BOOT + marker, variant)
            for invalid in (b"", marker, BOOT, BOOT + marker + marker,
                            marker + BOOT, BOOT + EXPECTED["normal"] + marker):
                if invalid != BOOT + marker:
                    with self.assertRaises(ValueError):
                        check_trace(invalid, variant)


if __name__ == "__main__":
    unittest.main()
