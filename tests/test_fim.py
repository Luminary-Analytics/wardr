"""Tests for lightweight File Integrity Monitoring (FIM)."""

from pathlib import Path
import tempfile
import unittest

from wardr import fim


class FileIntegrityMonitoringTests(unittest.TestCase):
    def test_baseline_init_verify_and_detect_modifications(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_dir = root / "state"
            cfg_a = root / "sshd_config"
            cfg_b = root / "authorized_keys"
            cfg_a.write_text("PasswordAuthentication no\n", encoding="utf-8")
            cfg_b.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA demo@host\n", encoding="utf-8")
            targets = [("sshd_config", cfg_a), ("authorized_keys", cfg_b)]

            # First check initializes cleanly.
            first = fim.check_integrity(state_dir, targets=targets)
            self.assertEqual(first["status"], "pass")
            self.assertEqual(first["tracked_count"], 2)
            self.assertEqual(first["changes"], [])

            # Unchanged files continue to pass.
            second = fim.check_integrity(state_dir, targets=targets)
            self.assertEqual(second["status"], "pass")
            self.assertEqual(second["changes"], [])

            # Tampering with sshd_config and deleting authorized_keys must fail with exact details.
            cfg_a.write_text("PasswordAuthentication yes\n", encoding="utf-8")
            cfg_b.unlink()
            third = fim.check_integrity(state_dir, targets=targets)
            self.assertEqual(third["status"], "fail")
            by_label = {row["label"]: row for row in third["changes"]}
            self.assertEqual(by_label["sshd_config"]["change"], "modified")
            self.assertNotEqual(by_label["sshd_config"]["previous_sha256"], by_label["sshd_config"]["current_sha256"])
            self.assertEqual(by_label["authorized_keys"]["change"], "removed_or_unreadable")


if __name__ == "__main__":
    unittest.main()
