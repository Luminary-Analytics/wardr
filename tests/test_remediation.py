"""Tests for transactional one-click remediation with preview and rollback."""

import os
from pathlib import Path
import platform
import stat
import tempfile
import unittest
from unittest.mock import patch

from wardr import remediation


@unittest.skipUnless(os.name == "posix" and platform.system() in ("Darwin", "Linux"), "POSIX permissions test")
class TransactionalRemediationTests(unittest.TestCase):
    def test_preview_apply_and_undo_credential_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            state_dir = root / "state"
            aws_dir = home / ".aws"
            aws_dir.mkdir(parents=True, mode=0o700)
            creds = aws_dir / "credentials"
            creds.write_text("[default]\naws_access_key_id=example\n", encoding="utf-8")
            os.chmod(creds, 0o644)

            with (
                patch("wardr.remediation._account_home", return_value=home),
                patch("wardr.remediation._can_repair_posix", return_value=True),
                patch("wardr.remediation._acl_absent", return_value=True),
            ):
                checks = {c["id"]: c for c in remediation.credential_checks()}
                self.assertEqual(checks["aws-credentials-permissions"]["status"], "fail")
                self.assertTrue(checks["aws-credentials-permissions"]["can_fix"])

                preview = remediation.preview_fix("aws-credentials-permissions")
                self.assertTrue(preview["eligible"])
                self.assertTrue(preview["reversible"])
                self.assertEqual(preview["changes"][0]["current_mode"], "0644")
                self.assertEqual(preview["changes"][0]["target_mode"], "0600")

                applied = remediation.apply_fix("aws-credentials-permissions", state_dir=state_dir)
                self.assertTrue(applied["ok"])
                self.assertEqual(applied["check"]["status"], "pass")
                self.assertIsNotNone(applied["rollback_id"])
                self.assertEqual(stat.S_IMODE(creds.stat().st_mode), 0o600)

                history = remediation.list_history(state_dir)
                self.assertEqual(len(history), 1)
                self.assertTrue(history[0]["can_undo"])

                undone = remediation.undo_fix(applied["rollback_id"], state_dir)
                self.assertTrue(undone["ok"])
                self.assertEqual(stat.S_IMODE(creds.stat().st_mode), 0o644)
                self.assertEqual(undone["check"]["status"], "fail")

                # Double undo must be refused.
                again = remediation.undo_fix(applied["rollback_id"], state_dir)
                self.assertFalse(again["ok"])

    def test_rollback_refuses_if_file_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            state_dir = root / "state"
            kube_dir = home / ".kube"
            kube_dir.mkdir(parents=True, mode=0o700)
            cfg = kube_dir / "config"
            cfg.write_text("apiVersion: v1\n", encoding="utf-8")
            os.chmod(cfg, 0o644)

            with (
                patch("wardr.remediation._account_home", return_value=home),
                patch("wardr.remediation._can_repair_posix", return_value=True),
                patch("wardr.remediation._acl_absent", return_value=True),
            ):
                applied = remediation.apply_fix("kube-config-permissions", state_dir=state_dir)
                self.assertTrue(applied["ok"])

                # Replace file with a different inode.
                cfg.unlink()
                cfg.write_text("replaced\n", encoding="utf-8")
                os.chmod(cfg, 0o600)

                undone = remediation.undo_fix(applied["rollback_id"], state_dir)
                self.assertFalse(undone["ok"])
                self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
