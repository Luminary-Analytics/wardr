"""Tests for Red / Amber / Green posture assessment, active threats, and visual reports."""

import re
import tempfile
import unittest
from pathlib import Path

from wardr.report import assess_posture, html_report, report_data
from wardr.state import WardrState


HOST = {"name": "workstation-1", "os": "macOS", "version": "15.2"}


def _check(check_id, title, status, severity="medium", can_fix=False):
    return {
        "id": check_id,
        "title": title,
        "category": "System",
        "severity": severity,
        "status": status,
        "can_fix": can_fix,
        "risk": "Sample risk.",
        "evidence": "Observed state.",
        "remediation": "Apply control.",
    }


class PostureAndVisualReportTests(unittest.TestCase):
    def test_green_when_all_securable_checks_pass_and_no_threats(self):
        scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [
                _check("fw", "Firewall", "pass", "high"),
                _check("fv", "FileVault", "pass", "high"),
                _check("na", "Windows Defender", "not_applicable", "high"),
            ],
        }
        posture = assess_posture(
            scan,
            monitoring={"running": True, "interval": 30},
            threats={"status": "clear", "count": 0},
        )
        self.assertEqual(posture["level"], "green")
        self.assertTrue(posture["as_safe_as_possible"])
        self.assertEqual(posture["secured"], 2)
        self.assertEqual(posture["securable_total"], 2)
        self.assertEqual(posture["coverage_pct"], 100)

    def test_amber_when_medium_finding_or_unverified_exists(self):
        scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [
                _check("fw", "Firewall", "pass", "high"),
                _check("ssh", "SSH key permissions", "fail", "medium", can_fix=True),
            ],
        }
        posture = assess_posture(scan, monitoring={"running": True}, threats={"status": "clear", "count": 0})
        self.assertEqual(posture["level"], "amber")
        self.assertFalse(posture["as_safe_as_possible"])
        self.assertEqual(posture["fixable"], 1)
        self.assertEqual(posture["coverage_pct"], 50)

        unverified_scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [
                _check("fw", "Firewall", "pass", "high"),
                _check("upd", "OS updates", "unknown", "high"),
            ],
        }
        posture_unknown = assess_posture(unverified_scan, monitoring={"running": True}, threats={"status": "clear", "count": 0})
        self.assertEqual(posture_unknown["level"], "amber")
        self.assertFalse(posture_unknown["as_safe_as_possible"])

    def test_red_when_high_finding_or_active_threat(self):
        scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [
                _check("fw", "Firewall", "fail", "high"),
                _check("fv", "FileVault", "pass", "high"),
            ],
        }
        posture = assess_posture(scan, monitoring={"running": True}, threats={"status": "clear", "count": 0})
        self.assertEqual(posture["level"], "red")

        clean_scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [_check("fw", "Firewall", "pass", "high")],
        }
        threat_posture = assess_posture(
            clean_scan,
            monitoring={"running": True},
            threats={"status": "threat", "count": 2},
        )
        self.assertEqual(threat_posture["level"], "red")
        self.assertEqual(threat_posture["label"], "Active threat")

    def test_html_report_renders_rag_shield_checklist_and_respects_csp(self):
        scan = {
            "scanned_at": "2026-11-22T08:00:00+00:00",
            "checks": [
                _check("fw", "Application Firewall", "pass", "high"),
                _check("ssh", "SSH Permissions", "fail", "medium", can_fix=True),
            ],
        }
        data = report_data(
            HOST,
            scan,
            monitoring={"running": True, "interval": 30, "poll_count": 4},
            threats={"status": "clear", "count": 0},
        )
        self.assertEqual(data["posture"]["level"], "amber")
        markup = html_report(data)
        self.assertIn("rag-amber", markup)
        self.assertIn("<svg viewBox=\"0 0 100 112\"", markup)
        self.assertIn("No active threats detected", markup)
        self.assertIn("Secured checks (1)", markup)
        self.assertIn("Needs attention (1)", markup)
        # Strict CSP prohibits inline style="..." attributes.
        self.assertIsNone(re.search(r'\sstyle\s*=', markup, re.I))

    def test_state_status_includes_posture_threats_and_poll_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp))
            payload = state.status()
            self.assertIn("posture", payload)
            self.assertIn("threats", payload)
            self.assertEqual(payload["posture"]["level"], "pending")
            self.assertEqual(payload["threats"]["status"], "clear")
            self.assertIn("poll_count", payload["monitoring"])

    def test_static_assets_have_no_inline_styles_for_strict_csp(self):
        static_dir = Path(__file__).resolve().parent.parent / "wardr" / "static"
        index_html = (static_dir / "index.html").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r'\sstyle\s*=', index_html, re.I))
        wardr_js = (static_dir / "wardr.js").read_text(encoding="utf-8")
        self.assertNotIn(".style.", wardr_js)
        self.assertNotIn('setAttribute("style"', wardr_js)

    def test_queued_and_acknowledged_dispositions_reach_green_and_auto_clear_on_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp))
            upd = _check("macos-pending-updates", "macOS security updates", "fail", "high")
            upd["category"] = "Updates"
            upd["evidence"] = "macOS 26.7.3 update is available."
            fw = _check("macos-firewall", "Application Firewall", "pass", "high")
            state._scan = {
                "host": state.host["name"],
                "scanned_at": "2026-11-22T09:00:00+00:00",
                "checks": [fw, upd],
            }
            # Without disposition, posture is red.
            before = state.status()
            self.assertEqual(before["posture"]["level"], "red")
            self.assertEqual(before["posture"]["failed"], 1)

            # Mark OS update queued (pending restart) -> persists and transitions to green (when monitor running) or amber (paused).
            res = state.set_check_disposition("macos-pending-updates", "queued", note="Restarting tonight")
            self.assertTrue(res["ok"])
            self.assertEqual(res["disposition"]["kind"], "queued")
            self.assertTrue(state.dispositions_path.exists())

            snap = state.enriched_scan_snapshot()
            posture = assess_posture(snap, monitoring={"running": True}, threats={"status": "clear", "count": 0})
            self.assertEqual(posture["level"], "green")
            self.assertTrue(posture["as_safe_as_possible"])
            self.assertEqual(posture["secured"], 1)
            self.assertEqual(posture["handled"], 1)
            self.assertEqual(posture["queued"], 1)
            self.assertEqual(posture["addressed"], 2)
            self.assertEqual(posture["failed"], 0)
            self.assertEqual(posture["coverage_pct"], 100)
            self.assertIn("1 queued (pending restart)", posture["summary"])

            # Report HTML renders the queued label with zero inline styles.
            rdata = report_data(HOST, snap, monitoring={"running": True}, threats={"status": "clear", "count": 0})
            self.assertEqual(rdata["summary"]["action_needed"], 0)
            self.assertEqual(rdata["summary"]["handled"], 1)
            markup = html_report(rdata)
            self.assertIn("rag-green", markup)
            self.assertIn("Queued · Pending restart", markup)
            self.assertIsNone(re.search(r'\sstyle\s*=', markup, re.I))

            # Reload from disk in a fresh WardrState instance to verify persistence.
            reloaded = WardrState(Path(tmp))
            reloaded._scan = state._scan
            reloaded_snap = reloaded.enriched_scan_snapshot()
            reloaded_upd = next(c for c in reloaded_snap["checks"] if c["id"] == "macos-pending-updates")
            self.assertEqual(reloaded_upd["disposition"]["kind"], "queued")

            # If Apple releases a newer version (evidence changes), disposition auto-clears and returns to red!
            newer_upd = {**upd, "evidence": "macOS 26.7.4 update is available."}
            reloaded._scan = {
                "host": reloaded.host["name"],
                "scanned_at": "2026-11-23T09:00:00+00:00",
                "checks": [fw, newer_upd],
            }
            changed_snap = reloaded.enriched_scan_snapshot()
            changed_upd = next(c for c in changed_snap["checks"] if c["id"] == "macos-pending-updates")
            self.assertNotIn("disposition", changed_upd)
            self.assertEqual(
                assess_posture(changed_snap, monitoring={"running": True}, threats={"status": "clear", "count": 0})["level"],
                "red",
            )

            # Clear / Undo restores immediately.
            state.set_check_disposition("macos-pending-updates", "clear")
            restored = state.enriched_scan_snapshot()
            restored_upd = next(c for c in restored["checks"] if c["id"] == "macos-pending-updates")
            self.assertNotIn("disposition", restored_upd)

    def test_acknowledging_failing_security_controls_cannot_fake_green_shield(self):
        from wardr import actions, inventory, pentest
        import os
        import stat

        with tempfile.TemporaryDirectory() as tmp:
            state = WardrState(Path(tmp), offline=True)
            fw_fail = _check("macos-firewall", "Application firewall", "fail", "high")
            fw_fail["evidence"] = "The macOS application firewall is disabled."
            gpg_fail = _check("gnupg-directory-permissions", "GnuPG directory permissions", "fail", "medium", can_fix=True)
            gpg_fail["evidence"] = "The current account's ~/.gnupg directory has POSIX mode 0755."
            sip_pass = _check("macos-sip", "System Integrity Protection", "pass", "high")
            state._scan = {
                "host": state.host["name"],
                "scanned_at": "2026-11-25T10:00:00+00:00",
                "checks": [sip_pass, fw_fail, gpg_fail],
            }

            # 1. Auto-fixable failing checks cannot be acknowledged instead of fixed.
            with self.assertRaises(ValueError):
                state.set_check_disposition("gnupg-directory-permissions", "acknowledged")
            with self.assertRaises(ValueError):
                state.set_check_dispositions_batch(["gnupg-directory-permissions"], "acknowledged")

            # 2. Non-update checks cannot use 'queued' disposition.
            with self.assertRaises(ValueError):
                state.set_check_disposition("macos-firewall", "queued")

            # 3. Acknowledging a failing non-update OS control keeps posture Amber (never Green).
            state._scan["checks"] = [sip_pass, fw_fail]
            state.set_check_disposition("macos-firewall", "acknowledged", note="Lab exception")
            snap = state.enriched_scan_snapshot()
            posture = assess_posture(snap, monitoring={"running": True}, threats={"status": "clear", "count": 0})
            self.assertEqual(posture["level"], "amber")
            self.assertEqual(posture["label"], "Risk accepted")
            self.assertFalse(posture["as_safe_as_possible"])
            self.assertEqual(posture["accepted_risks"], 1)
            self.assertEqual(posture["coverage_pct"], 50)
            self.assertIn("accepted risk", posture["summary"].lower())

            # Defense matrix also refuses to mark network-intrusion green when firewall is still failing.
            matrix = pentest.build_defense_matrix(
                scan=snap,
                monitoring={"running": True, "poll_count": 1},
                threats={"status": "clear", "count": 0},
                exposure_result={"listeners": []},
                software_result=None,
                advisories=None,
                pentest_result=None,
            )
            net_domain = next(d for d in matrix["domains"] if d["id"] == "network-intrusion")
            self.assertNotEqual(net_domain["level"], "green")

            # HTML report labels it honestly as Accepted risk (still failing) in amber hero.
            markup = html_report(report_data(HOST, snap, monitoring={"running": True}, threats={"status": "clear", "count": 0}))
            self.assertIn("rag-amber", markup)
            self.assertIn("Accepted risk (still failing)", markup)

            # 4. Gatekeeper macOS script uses --global-enable with --master-enable fallback.
            gk = actions.action_guide_for("macos-gatekeeper", system="Darwin")
            self.assertIsNotNone(gk)
            self.assertIn("--global-enable", gk["script_preview"])

            # 5. Inventory cache is written with private 0600 permissions on POSIX.
            inventory.collect_inventory(Path(tmp), include_python=False, force=True)
            cache_file = Path(tmp) / "inventory-cache.json"
            self.assertTrue(cache_file.exists())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(cache_file.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
