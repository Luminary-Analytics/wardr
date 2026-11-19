"""Regression coverage for time windows and evidence attribution."""

from datetime import datetime, timedelta, timezone
import unittest

from wardr.hunting import analyze


NOW = datetime(2026, 11, 19, 18, tzinfo=timezone.utc)


def event(identifier, minutes_ago, title, source, detail=""):
    return {
        "id": str(identifier),
        "at": (NOW - timedelta(minutes=minutes_ago)).isoformat(),
        "title": title,
        "source": source,
        "detail": detail,
    }


def hunt(events, **status):
    return analyze({"events": events, **status}, now=NOW)


def listener(identifier, minutes_ago, endpoint):
    return event(identifier, minutes_ago, "New non-loopback TCP listener", "TCP listeners",
                 f"A local service began listening on {endpoint}. Review the service if the change is unexpected.")


class ThreatHuntingTests(unittest.TestCase):
    def test_authentication_window_keeps_unique_evidence_and_source(self):
        linux_title = "SSH authentication failed"
        linux_source = "Linux SSH journal"
        events = [event("early", 10, linux_title, linux_source)]
        events.extend(event(i, age, linux_title, linux_source) for i, age in enumerate((6, 5, 4, 3, 2, 1)))
        events.append(events[-1].copy())
        events.extend(event(f"windows-{i}", 1, "Windows sign-in failed", "Windows Security log") for i in range(5))

        results = hunt(list(reversed(events)))
        alert, = results["alerts"]
        self.assertEqual(alert["rule_id"], "authentication-failure-burst")
        self.assertEqual(alert["confidence"], "medium")
        self.assertEqual(alert["event_ids"], ["0", "1", "2", "3", "4", "5"])
        self.assertEqual([item["at"] for item in alert["evidence"]], [item["at"] for item in events[1:7]])
        self.assertTrue(all(item["source"] == linux_source for item in alert["evidence"]))
        self.assertEqual(hunt(events)["alerts"], results["alerts"])

    def test_windows_correlations_require_supported_sources_and_order(self):
        records = [
            event("earlier", 13, "Windows service installed", "Windows System log"),
            event("defender", 12, "Defender real-time protection disabled", "Microsoft Defender log"),
            event("same-minute", 12, "Windows account created", "Windows Security log"),
            event("install", 10, "Windows service installed", "Windows System log"),
            event("wrong-source", 9, "Windows service installed", "Local system"),
            event("account", 4, "Windows account created", "Windows Security log"),
            event("too-late", 1, "Windows service installed", "Windows System log"),
        ]
        alert, = hunt(records)["alerts"]
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["confidence"], "medium")
        self.assertEqual(alert["event_ids"], ["defender", "install", "account"])
        standalone, = hunt(records[:2])["alerts"]
        self.assertEqual(standalone["confidence"], "high")
        self.assertEqual(standalone["id"], alert["id"])

    def test_coverage_waiting_uses_history_and_invalid_times_stay_out(self):
        signal = ("Microsoft Defender detection", "Microsoft Defender log")
        recent = event("detected", 20, *signal)
        stale = event("stale", 1500, *signal)
        future = event("future", -5, *signal)
        invalid = {**event("invalid", 5, *signal), "at": "2026-11-19T12:34:56"}
        results = hunt([recent, stale, future, invalid], coverage=[{
            "id": "windows-defender", "label": "Microsoft Defender log", "available": None,
        }])
        self.assertEqual(results["coverage_state"], "waiting")
        self.assertIn("retained event history", results["coverage_note"])
        self.assertEqual(results["events_considered"], 1)
        self.assertEqual(results["alerts"][0]["event_ids"], ["detected"])
        self.assertEqual(results["alerts"][0]["confidence"], "high")

    def test_ipv4_and_ipv6_observations_on_same_port_only_count_once(self):
        records = [
            listener("one-v4", 4, "0.0.0.0:443"),
            listener("one-v6", 4, "[::]:443"),
            listener("two", 3, "*:8443"),
        ]
        self.assertEqual(hunt(records)["alerts"], [])
        records.append(listener("three", 2, "192.0.2.50:8080"))
        alert, = hunt(records)["alerts"]
        self.assertEqual(alert["rule_id"], "tcp-listener-burst")
        self.assertIn("3 distinct TCP port numbers", alert["summary"])
        self.assertEqual(len(alert["evidence"]), 4)

    def test_macos_changes_only_correlate_with_listeners_from_same_sample(self):
        records = [
            listener("port", 5, "192.0.2.50:8080"),
            event("older", 6, "macOS launch item changed", "macOS launch items",
                  "Added com.example.older.plist in System LaunchDaemons."),
            event("remove", 5, "macOS launch item changed", "macOS launch items",
                  "Removed com.example.remove.plist in System LaunchDaemons."),
            event("match", 5, "macOS launch item changed", "macOS launch items",
                  "Changed com.example.current.plist in System LaunchDaemons."),
        ]
        alert, = hunt(records)["alerts"]
        self.assertEqual(alert["rule_id"], "launch-daemon-and-listener")
        self.assertEqual(alert["event_ids"], ["match", "port"])
        self.assertEqual(alert["confidence"], "medium")

    def test_partial_coverage_and_bounded_alerts_are_explicit(self):
        records = [event(i, i, "Windows Security log cleared", "Windows Security log") for i in range(50)]
        results = hunt(records, last_poll=NOW.isoformat(), coverage=[
            {"id": "windows-security", "available": True},
            {"id": "windows-system", "available": False},
        ])
        self.assertEqual(results["coverage_state"], "partial")
        self.assertEqual(len(results["alerts"]), 40)
        self.assertEqual(results["alerts_omitted"], 10)
        self.assertEqual(results["alerts"][0]["event_ids"], ["0"])


if __name__ == "__main__":
    unittest.main()
