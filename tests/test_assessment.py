import json
import tempfile
import unittest
from pathlib import Path

from wardr.assessment import AssessmentError, assess, assess_documents


def bom(*purls):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"purl": item} for item in purls]}


def affected(ecosystem, name, **data):
    return {"package": {"ecosystem": ecosystem, "name": name}, **data}


def advisory(identifier, *entries, **metadata):
    return {"id": identifier, "modified": "2026-11-18T10:00:00Z", "affected": list(entries), **metadata}


def timeline(*events, kind="SEMVER"):
    return {"type": kind, "events": [dict([item]) for item in events]}


class AdvisoryAssessmentTests(unittest.TestCase):
    def test_exact_identity_and_exploitation_requires_a_version_match(self):
        record = advisory(
            "TEST-1", affected("PyPI", "Sample_Project", versions=["1.2.0"]),
            aliases=["CVE-2026-12345"],
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        )
        result = assess_documents(
            bom("pkg:pypi/sample.project@1.2.0", "pkg:pypi/sample.project@1.2.1",
                "pkg:npm/sample-project@1.2.0", "pkg:pypi/sample.project@1.2.0?repository_url=https%3A%2F%2Fexample.test"),
            record,
            exploited_ids={"CVE-2026-12345"},
        )
        self.assertEqual(result["summary"]["matched_findings"], 1)
        self.assertEqual(result["summary"]["packages_with_advisory_entries"], 2)
        self.assertEqual(result["summary"]["packages_without_advisory_entries"], 2)
        row = result["findings"][0]
        self.assertEqual(row["confidence"], "exact_version")
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["cvss_base_score"], 9.8)
        self.assertTrue(row["known_exploited"])
        self.assertEqual(row["fixed_versions"], [])
        self.assertEqual(row["source_url"], "https://osv.dev/vulnerability/TEST-1")

    def test_semver_prerelease_bounds_and_fixed_version(self):
        selected = timeline(("fixed", "1.1.0"), ("introduced", "1.1.0-beta.2"))
        record = advisory("TEST-2", affected("npm", "@team/sample", ranges=[selected]))
        result = assess_documents(
            bom("pkg:npm/%40team/sample@1.1.0-beta.1", "pkg:npm/%40team/sample@1.1.0-beta.2",
                "pkg:npm/%40team/sample@1.1.0-beta.10", "pkg:npm/%40team/sample@1.1.0%2Bbuild"),
            [record],
        )
        self.assertEqual({item["version"] for item in result["findings"]}, {"1.1.0-beta.2", "1.1.0-beta.10"})
        for item in result["findings"]:
            self.assertEqual(item["confidence"], "affected_range")
            self.assertEqual(item["fixed_versions"], ["1.1.0"])
            self.assertEqual(item["severity"], "unknown")

    def test_limit_and_inclusive_last_affected(self):
        selected = timeline(("introduced", "0"), ("last_affected", "2.0.0"), ("limit", "2.1.0"))
        record = advisory("TEST-3", affected("npm", "sample", ranges=[selected]))
        result = assess_documents(bom("pkg:npm/sample@2.0.0", "pkg:npm/sample@2.0.1"), record)
        self.assertEqual([item["version"] for item in result["findings"]], ["2.0.0"])
        self.assertEqual(result["findings"][0]["fixed_versions"], [])
        limited = timeline(("introduced", "0"), ("limit", "2.0.0"), ("limit", "1.9.0"))
        record["affected"][0]["ranges"] = [limited]
        result = assess_documents(bom("pkg:npm/sample@1.9.0", "pkg:npm/sample@2.0.0"), record)
        self.assertEqual([item["version"] for item in result["findings"]], ["1.9.0"])

    def test_pypi_release_range_reports_unsupported_version(self):
        selected = timeline(("introduced", "1!1.0"), ("fixed", "1!2.1.0"), kind="ECOSYSTEM")
        record = advisory("TEST-4", affected("PyPI", "sample", ranges=[selected]))
        result = assess_documents(
            bom("pkg:pypi/sample@1%212.0", "pkg:pypi/sample@1%212.1", "pkg:pypi/sample@1%212.0rc1",
                "pkg:pypi/sample@2.0"),
            record,
        )
        self.assertEqual([item["version"] for item in result["findings"]], ["1!2.0"])
        self.assertEqual(result["findings"][0]["fixed_versions"], ["1!2.1.0"])
        self.assertEqual(result["summary"]["coverage_gaps"], 1)
        self.assertEqual(result["coverage_gaps"][0]["version"], "1!2.0rc1")

    def test_unsupported_range_keeps_exact_match_but_suppresses_fix_guess(self):
        ranges = [timeline(("introduced", "0"), ("fixed", "2.0.0")), timeline(("introduced", "0"), kind="GIT")]
        record = advisory("TEST-5", affected("npm", "sample", versions=["1.0.0"], ranges=ranges))
        result = assess_documents(bom("pkg:npm/sample@1.0.0"), record)
        self.assertEqual(result["summary"]["matched_findings"], 1)
        self.assertEqual(result["summary"]["coverage_gaps"], 1)
        self.assertEqual(result["findings"][0]["confidence"], "exact_version")
        self.assertEqual(result["findings"][0]["fixed_versions"], [])

    def test_distinct_release_scopes_do_not_match_across_distributions(self):
        entry = affected("Debian:12", "sample", versions=["7.0"])
        entry["package"]["purl"] = "pkg:deb/debian/sample?distro=debian-12"
        inputs = bom(
            "pkg:deb/debian/sample@7.0?distro=debian-12",
            "pkg:deb/debian/sample@7.0?distro=debian-13",
            "pkg:deb/ubuntu/sample@7.0?distro=ubuntu-22.04",
        )
        result = assess_documents(inputs, advisory("TEST-6", entry))
        self.assertEqual([item["ecosystem"] for item in result["findings"]], ["Debian:12"])
        entry["package"]["ecosystem"] = "Debian:13"
        result = assess_documents(inputs, advisory("TEST-6", entry))
        self.assertEqual(result["summary"]["matched_findings"], 0)
        self.assertEqual(result["advisories"]["unidentified_affected_entries"], 1)

    def test_withdrawn_and_malformed_records_and_conflicting_bom_versions(self):
        entry = affected("Go", "example.test/sample", versions=["1.2.0"])
        original = advisory("TEST-7", entry)
        withdrawn = {**original, "modified": "2026-11-18T11:00:00Z", "withdrawn": "2026-11-18T11:00:00Z"}
        inputs = bom("pkg:golang/example.test/sample@v1.2.0")
        inputs["components"].append({"purl": "pkg:golang/example.test/sample@1.2.0", "version": "3.0.0"})
        result = assess_documents(inputs, {"vulns": [original, withdrawn, {"id": "INCOMPLETE"}, {"id": []}]})
        self.assertEqual(result["summary"]["matched_findings"], 0)
        self.assertEqual(result["inventory"]["skipped_components"], 1)
        self.assertEqual(result["advisories"]["withdrawn"], 1)
        self.assertEqual(result["advisories"]["invalid_records"], 2)
        result = assess_documents(inputs, original)
        self.assertEqual(result["summary"]["matched_findings"], 1)

    def test_local_files_only_and_invalid_inputs_report_an_error(self):
        with tempfile.TemporaryDirectory() as storage:
            directory = Path(storage)
            inventory = directory / "sbom.json"
            source = directory / "advisory.json"
            inventory.write_text(json.dumps(bom("pkg:pypi/sample@1.0")), encoding="utf-8")
            source.write_text(
                json.dumps(advisory("TEST-8", affected("PyPI", "sample", versions=["1.0"]))),
                encoding="utf-8",
            )
            self.assertEqual(assess(inventory, source)["summary"]["matched_findings"], 1)
            source.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(AssessmentError, "not valid JSON"):
                assess(inventory, [source])
            with self.assertRaisesRegex(AssessmentError, "regular local files"):
                assess(inventory, [directory])
