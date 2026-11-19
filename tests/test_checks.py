"""Regression tests for trust boundaries in posture checks and remediation."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch
import os
import platform
import plistlib
import stat
import subprocess

from wardr import checks


@skipUnless(os.name == "posix" and os.getuid() != 0, "requires an unprivileged POSIX account")
class SSHRepairTests(TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory()) if hasattr(self, "enterContext") else None
        if directory is None:
            temporary = TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            directory = temporary.name
        self.home = Path(directory)
        passwd = patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=directory))
        passwd.start()
        self.addCleanup(passwd.stop)

    def _fixture_file(self, name, mode, content="synthetic fixture"):
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700, exist_ok=True)
        path = ssh / name
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_only_removes_group_and_other_mode_bits(self):
        ssh = self.home / ".ssh"
        ssh.mkdir()
        ssh.chmod(0o755)
        finding = checks._ssh_check()
        self.assertEqual(finding["status"], "fail")
        self.assertTrue(finding["can_fix"])

        result = checks.apply_fix("ssh-directory-permissions")
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"]["status"], "pass")
        self.assertEqual(stat.S_IMODE(ssh.stat().st_mode), 0o700)

        repeat = checks.apply_fix("ssh-directory-permissions")
        self.assertTrue(repeat["ok"])
        self.assertIn("already", repeat["message"])

    def test_rejects_symlinks_and_unlisted_actions(self):
        target = self.home / "other"
        target.mkdir()
        target.chmod(0o755)
        (self.home / ".ssh").symlink_to(target, target_is_directory=True)

        self.assertEqual(checks._ssh_check()["status"], "unknown")
        self.assertFalse(checks.apply_fix("macos-firewall")["ok"])
        self.assertFalse(checks.apply_fix("ssh-directory-permissions")["ok"])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_identity_repair_only_touches_standard_identity_modes(self):
        key = self._fixture_file("id_ed25519", 0o644)
        owner_read_only = self._fixture_file("id_rsa", 0o444)
        public = self._fixture_file("id_ed25519.pub", 0o644)
        custom = self._fixture_file("my-custom-key", 0o644)
        identifier = "ssh-identity-permissions"

        finding = checks._ssh_file_check(identifier)
        self.assertEqual(finding["status"], "fail")
        self.assertTrue(finding["can_fix"])
        self.assertNotIn("synthetic fixture", str(finding))
        result = checks.apply_fix(identifier)
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"]["status"], "pass")
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(owner_read_only.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(custom.stat().st_mode), 0o644)
        self.assertEqual(key.read_text(encoding="utf-8"), "synthetic fixture")
        self.assertTrue(checks.apply_fix(identifier)["ok"])

    def test_authorized_keys_repair_preserves_read_permissions(self):
        path = self._fixture_file("authorized_keys", 0o666)
        legacy = self._fixture_file("authorized_keys2", 0o640)
        key = self._fixture_file("id_ed25519", 0o644)
        identifier = "ssh-authorized-keys-permissions"

        self.assertTrue(checks._ssh_file_check(identifier)["can_fix"])
        result = checks.apply_fix(identifier)
        self.assertTrue(result["ok"])
        self.assertEqual(result["check"]["status"], "pass")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(legacy.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o644)

    def test_linked_or_special_files_block_the_batch(self):
        ordinary = self._fixture_file("id_ed25519", 0o644)
        elsewhere = self.home / "another-link"
        linked = self._fixture_file("id_rsa", 0o644)
        os.link(linked, elsewhere)
        (linked.parent / "id_dsa").symlink_to(ordinary)
        os.mkfifo(linked.parent / "id_ecdsa")
        identifier = "ssh-identity-permissions"

        finding = checks._ssh_file_check(identifier)
        self.assertEqual(finding["status"], "fail")
        self.assertFalse(finding["can_fix"])
        self.assertFalse(checks.apply_fix(identifier)["ok"])
        self.assertEqual(stat.S_IMODE(ordinary.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(elsewhere.stat().st_mode), 0o644)

    def test_untrusted_directory_mode_blocks_file_repair(self):
        path = self._fixture_file("authorized_keys", 0o666)
        path.parent.chmod(0o777)
        identifier = "ssh-authorized-keys-permissions"

        self.assertFalse(checks._ssh_file_check(identifier)["can_fix"])
        self.assertFalse(checks.apply_fix(identifier)["ok"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o666)

    @skipUnless(platform.system() == "Darwin", "exercises native macOS ACLs")
    def test_extended_acl_disables_automatic_repair(self):
        key = self._fixture_file("id_ed25519", 0o644)
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(key)], check=True)
        identifier = "ssh-identity-permissions"

        self.assertFalse(checks._ssh_file_check(identifier)["can_fix"])
        self.assertFalse(checks.apply_fix(identifier)["ok"])
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o644)
        self.assertIn(b"everyone allow read", subprocess.check_output(["/bin/ls", "-le", str(key)]))

    @skipUnless(platform.system() == "Darwin", "exercises native macOS ACLs")
    def test_directory_with_extended_acl_requires_manual_review(self):
        ssh = self.home / ".ssh"
        ssh.mkdir(mode=0o700)
        subprocess.run(["/bin/chmod", "+a", "everyone allow list", str(ssh)], check=True)
        self.assertEqual(checks._ssh_check()["status"], "unknown")

        ssh.chmod(0o755)
        self.assertEqual(checks._ssh_check()["status"], "fail")
        self.assertFalse(checks._ssh_check()["can_fix"])
        self.assertFalse(checks.apply_fix("ssh-directory-permissions")["ok"])
        self.assertEqual(stat.S_IMODE(ssh.stat().st_mode), 0o755)
        self.assertIn(b"everyone allow list", subprocess.check_output(["/bin/ls", "-led", str(ssh)]))


class PatchStatusTests(TestCase):
    def test_macos_current_track_matches_and_stale_candidates_are_unknown(self):
        version = {"Display Version": "26.7", "Identifier": "MSU_UPDATE_CURRENT"}
        major_upgrade = {"Display Version": "27.1", "Identifier": "MSU_UPDATE_MAJOR"}
        current = datetime.now(timezone.utc).replace(tzinfo=None)
        fixtures = (
            (current, [version, major_upgrade], "fail"),
            (current, [major_upgrade], "pass"),
            (current - timedelta(days=15), [version], "unknown"),
        )
        for stamp, recommendations, expected in fixtures:
            with self.subTest(expected=expected):
                raw = plistlib.dumps({
                    "LastSuccessfulDate": stamp,
                    "RecommendedUpdates": recommendations,
                }).decode()
                with patch.object(checks, "_run", return_value=raw):
                    with patch.object(checks.platform, "mac_ver", return_value=("26.6", (), "")):
                        pending, background = checks._macos_patches()
                self.assertEqual(pending["status"], expected)
                self.assertEqual(background["status"], "unknown")
                self.assertNotIn("27.1", pending["evidence"])

    def test_windows_cache_without_a_date_cannot_produce_a_pass(self):
        with patch.object(checks, "_powershell", return_value={"count": 0}):
            self.assertEqual(checks._windows_patches()["status"], "unknown")

        fresh = datetime.now(timezone.utc).isoformat()
        with patch.object(checks, "_powershell", return_value={"count": 1, "date": fresh}):
            self.assertEqual(checks._windows_patches()["status"], "fail")

    def test_linux_apt_uses_local_security_candidates(self):
        output = (
            "Inst security-package [1] (2 Debian-Security:12/stable-security [amd64])\n"
            "Inst ordinary-package [1] (2 Debian:12/stable [amd64])\n"
        )
        with patch.object(checks.Path, "is_file", return_value=True):
            with patch.object(checks, "_apt_security_cache_date", return_value=datetime.now(timezone.utc)):
                with patch.object(checks, "_run", return_value=output) as run:
                    result = checks._linux_patches()
        self.assertEqual(result["status"], "fail")
        self.assertIn("security-package", result["evidence"])
        self.assertNotIn("ordinary-package", result["evidence"])
        self.assertIn("--simulate", run.call_args.args)
        self.assertIn("--no-download", run.call_args.args)
