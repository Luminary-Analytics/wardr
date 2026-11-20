"""Exercise release integrity gates without contacting GitHub."""

from contextlib import redirect_stderr
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


SPEC = spec_from_file_location(
    "wardr_release_github", Path(__file__).resolve().parents[1] / "packaging/release_github.py",
)
github = module_from_spec(SPEC)
SPEC.loader.exec_module(github)

VERSION = "0.3.4"
COMMIT = "a" * 40
SIGNING_TAG = "sign-v0.3.4"


def digest(data):
    return f"sha256:{sha256(data).hexdigest()}"


class VerifiedInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runs = dict(zip(github.SIGNING_WORKFLOWS, (11, 12, 13)))
        self.release = {"id": 37, "tag_name": f"v{VERSION}", "draft": True, "prerelease": True}
        self.assets = []
        self.bytes = {}
        self.contents = {}
        for asset_name, name in github._installer_assets(VERSION).items():
            content = asset_name.encode()
            self.contents[name] = content
            self.add_asset(asset_name, content)
        self.add_asset("staging-windows-1-1-unsigned-leftover.exe", b"left by a failed run")
        self.deleted = []
        api = patch.object(github, "_api", side_effect=self.api)
        cli = patch.object(github, "_gh", side_effect=self.cli)
        api.start()
        cli.start()
        self.addCleanup(api.stop)
        self.addCleanup(cli.stop)

    def add_asset(self, name, content):
        asset = {"id": 100 + len(self.assets), "name": name, "state": "uploaded",
                 "size": len(content), "digest": digest(content)}
        self.assets.append(asset)
        self.bytes[asset["id"]] = content
        return asset

    def api(self, endpoint, *options, **kwargs):
        path = urlsplit(endpoint).path
        if "/actions/runs/" in path:
            run_id = int(path.split("/runs/")[1])
            workflow = next(name for name, value in self.runs.items() if value == run_id)
            return {
                "id": run_id, "path": f".github/workflows/{workflow}", "head_branch": SIGNING_TAG,
                "head_sha": COMMIT, "event": "push", "status": "completed", "conclusion": "success",
            }
        if path.endswith("/releases"):
            return [[self.release.copy()]]
        if path.endswith("/releases/37/assets"):
            return [[asset.copy() for asset in self.assets]]
        self.assertIn("/releases/assets/", path)
        self.assertEqual(options, ("--method", "DELETE"))
        asset_id = int(path.rsplit("/", 1)[1])
        self.deleted.append(next(asset["name"] for asset in self.assets if asset["id"] == asset_id))
        self.assets = [asset for asset in self.assets if asset["id"] != asset_id]
        return {}

    def cli(self, *arguments, stdout, **kwargs):
        self.assertEqual(arguments[:3], ("api", "--hostname", "github.com"))
        self.assertIn("Accept: application/octet-stream", arguments)
        stdout.write(self.bytes[int(arguments[3].rsplit("/", 1)[1])])

    def test_installer_download_is_repeatable(self):
        for _ in range(2):
            files = github.fetch_installers(VERSION, self.runs, self.root / "installers")
            self.assertEqual({name: path.read_bytes() for name, path in files.items()}, self.contents)

    def test_rejects_wrong_asset_digest_before_writing_installers(self):
        self.assets[0]["digest"] = "sha256:" + "f" * 64
        destination = self.root / "installers"
        with self.assertRaisesRegex(github.ReleaseError, "does not match its GitHub size and digest"):
            github.fetch_installers(VERSION, self.runs, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_requires_every_installer_once_on_an_unpublished_draft(self):
        destination = self.root / "installers"
        self.add_asset(f"wardr-{VERSION}-linux-x64.run", b"a second copy")
        with self.assertRaisesRegex(github.ReleaseError, "Expected exactly one"):
            github.fetch_installers(VERSION, self.runs, destination)
        self.release["draft"] = False
        with self.assertRaisesRegex(github.ReleaseError, "unpublished draft"):
            github.fetch_installers(VERSION, self.runs, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_rejects_runs_from_another_tag(self):
        with patch.object(github, "SIGNING_TAG_PREFIX", "other-v"):
            with self.assertRaisesRegex(github.ReleaseError, "is not a successful"):
                github.fetch_installers(VERSION, self.runs, self.root / "installers")

    def test_tidy_removes_only_staging_files_and_the_proof(self):
        github.tidy_draft(VERSION)
        self.assertEqual(sorted(self.deleted),
                         sorted(["staging-windows-1-1-unsigned-leftover.exe", github.proof_asset(VERSION)]))
        self.assertEqual(len(self.assets), len(github._installer_assets(VERSION)) - 1)
        self.release["draft"] = False
        self.deleted.clear()
        github.tidy_draft(VERSION)
        self.assertEqual(self.deleted, [])

    def test_the_signing_tag_names_the_version(self):
        self.assertEqual(github.signing_tag(VERSION), SIGNING_TAG)
        with self.assertRaisesRegex(github.ReleaseError, "sign-vX.Y.Z"):
            github.wait_signing("vwardrsign-0_3_4", COMMIT, 60)


class DraftReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.files = [Path(temporary.name) / name for name in ("release.json", "release.json.sig")]
        self.release = {"id": 37, "tag_name": f"v{VERSION}", "draft": True, "prerelease": True}
        self.remote = {}
        self.writes = []
        for path in self.files:
            data = path.name.encode()
            path.write_bytes(data)
            self.remote[path.name] = {"name": path.name, "state": "uploaded", "size": len(data), "digest": digest(data)}
        api = patch.object(github, "_api", side_effect=self.api)
        cli = patch.object(github, "_gh", side_effect=AssertionError("Unexpected GitHub CLI call"))
        api.start()
        cli.start()
        self.addCleanup(api.stop)
        self.addCleanup(cli.stop)

    def api(self, endpoint, *options, **kwargs):
        if endpoint.startswith("https://uploads.github.com/"):
            name = parse_qs(urlsplit(endpoint).query)["name"][0]
            self.assertTrue(self.release["draft"])
            self.assertNotIn(name, self.remote)
            self.writes.append(("upload", name))
            data = Path(options[options.index("--input") + 1]).read_bytes()
            self.remote[name] = {"name": name, "state": "uploaded", "size": len(data), "digest": digest(data)}
            return self.remote[name]
        if "/assets?" in endpoint:
            return [list(self.remote.values())]
        if "/releases?" in endpoint:
            return [[self.release.copy()]]
        self.assertTrue(endpoint.endswith("/releases/37"))
        self.assertEqual(options, ("--method", "PATCH", "--field", "draft=false"))
        self.writes.append(("promote", 37))
        self.release["draft"] = False
        return self.release.copy()

    def test_draft_uploads_only_missing_asset_and_promotes_once(self):
        del self.remote["release.json.sig"]
        self.assertTrue(github.stage_draft(VERSION, self.files))
        self.assertTrue(github.stage_draft(VERSION, self.files))
        github.promote(VERSION, self.files)
        github.promote(VERSION, self.files)
        self.assertFalse(github.stage_draft(VERSION, self.files))
        self.assertEqual(self.writes, [("upload", "release.json.sig"), ("promote", 37)])

    def test_a_new_draft_keeps_the_community_prerelease_status(self):
        results = (None, None, self.release, self.release)
        with (
            patch.object(github, "_find_release", side_effect=results),
            patch.object(github, "_gh") as cli,
            patch.object(github, "sleep") as wait,
        ):
            self.assertTrue(github.stage_draft(VERSION, self.files))
        cli.assert_called_once()
        wait.assert_called_once_with(2)
        self.assertIn("--prerelease", cli.call_args.args)
        self.assertIn("--verify-tag", cli.call_args.args)

    def test_a_draft_for_the_installer_workflows_targets_the_reviewed_commit(self):
        results = (None, None, self.release, self.release)
        with (
            patch.object(github, "_find_release", side_effect=results),
            patch.object(github, "_gh") as cli,
            patch.object(github, "sleep"),
        ):
            self.assertTrue(github.stage_draft(VERSION, self.files, target=COMMIT))
        arguments = cli.call_args.args
        self.assertIn("--draft", arguments)
        self.assertIn("--prerelease", arguments)
        self.assertEqual(arguments[arguments.index("--target") + 1], COMMIT)
        self.assertNotIn("--verify-tag", arguments)

    def test_conflicting_existing_asset_blocks_staging(self):
        self.remote["release.json"]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(github.ReleaseError, "differs from"):
            github.stage_draft(VERSION, self.files)
        self.assertEqual(self.writes, [])

    def test_missing_or_changed_asset_blocks_promotion(self):
        self.assertTrue(github.stage_draft(VERSION, self.files))
        original = self.remote.pop("release.json.sig")
        with self.assertRaisesRegex(github.ReleaseError, "missing staged assets"):
            github.promote(VERSION, self.files)
        self.remote["release.json.sig"] = {**original, "size": original["size"] + 1}
        with self.assertRaisesRegex(github.ReleaseError, "differs from"):
            github.promote(VERSION, self.files)
        self.remote["release.json.sig"] = original
        self.files[1].write_bytes(b"Local bytes changed after staging")
        with self.assertRaisesRegex(github.ReleaseError, "differs from"):
            github.promote(VERSION, self.files)
        self.assertEqual(self.writes, [])


class LiveReleaseSmokeTests(unittest.TestCase):
    baseline = "0.3.3"
    run_id = 321
    workflow = "live-release.yml"
    endpoint = f"repos/Luminary-Analytics/wardr/actions/runs/{run_id}"
    run_url = f"https://github.com/Luminary-Analytics/wardr/actions/runs/{run_id}"

    def setUp(self):
        self.enterContext(redirect_stderr(StringIO()))
        self.api = self.enterContext(patch.object(github, "_api"))
        self.cli = self.enterContext(patch.object(github, "_gh"))
        self.sleep = self.enterContext(patch.object(github, "sleep"))

    def run_response(self, **changes):
        return {
            "id": self.run_id,
            "path": f".github/workflows/{self.workflow}@refs/tags/v{VERSION}",
            "head_branch": f"v{VERSION}",
            "head_sha": COMMIT,
            "event": "workflow_dispatch",
            "display_title": f"Wardr live upgrade {self.baseline} to {VERSION}",
            "status": "completed",
            "conclusion": "success",
            "run_attempt": 1,
            **changes,
        }

    def wait_for_run(self, **options):
        github.wait_live_release(self.run_id, VERSION, COMMIT, 60, baseline=self.baseline, **options)

    def test_dispatch_uses_exact_release_tag_and_version_pair(self):
        self.api.return_value = {"workflow_run_id": self.run_id}
        self.assertEqual(github.dispatch_live_release(self.baseline, VERSION), self.run_id)
        self.api.assert_called_once_with(
            f"repos/Luminary-Analytics/wardr/actions/workflows/{self.workflow}/dispatches",
            "--method", "POST", "--header", "X-GitHub-Api-Version: 2026-03-10",
            "--raw-field", f"ref=refs/tags/v{VERSION}",
            "--raw-field", f"inputs[baseline]={self.baseline}",
            "--raw-field", f"inputs[target]={VERSION}",
        )

    def test_dispatch_rejects_unsafe_inputs_without_contacting_github(self):
        for baseline, version in ((VERSION, VERSION), ("0.3.5", VERSION), (self.baseline, "main")):
            with self.subTest(baseline=baseline, version=version), self.assertRaises(github.ReleaseError):
                github.dispatch_live_release(baseline, version)
        self.api.assert_not_called()

    def test_dispatch_requires_a_valid_run_id(self):
        for response in (None, {}, {"workflow_run_id": True}, {"workflow_run_id": "321"}, {"workflow_run_id": 0}):
            with self.subTest(response=response), self.assertRaisesRegex(github.ReleaseError, "valid workflow run ID"):
                self.api.return_value = response
                github.dispatch_live_release(self.baseline, VERSION)

    def test_wait_polls_pending_run_until_the_pinned_run_succeeds(self):
        self.api.side_effect = (
            self.run_response(status="queued", conclusion=None),
            self.run_response(status="in_progress", conclusion=None),
            self.run_response(path=f".github/workflows/{self.workflow}"),
        )
        self.wait_for_run()
        self.assertEqual([call.args for call in self.api.call_args_list], [(self.endpoint,)] * 3)
        self.assertEqual(self.sleep.call_count, 2)
        self.cli.assert_not_called()

    def test_wait_rejects_success_from_wrong_run_provenance(self):
        changes = (
            {"id": self.run_id + 1},
            {"head_branch": f"v{self.baseline}"},
            {"head_sha": "b" * 40},
            {"event": "push"},
            {"display_title": f"Wardr live upgrade 0.3.2 to {VERSION}"},
            {"path": ".github/workflows/update-smoke.yml"},
            {"path": ".github/workflows/windows-live-release.yml"},
            {"path": f".github/workflows/{self.workflow}@refs/heads/main"},
        )
        for wrong in changes:
            with self.subTest(wrong=wrong), self.assertRaisesRegex(github.ReleaseError, "does not match"):
                self.api.return_value = self.run_response(**wrong)
                self.wait_for_run(retry_failed=True)
        self.assertEqual(self.api.call_count, len(changes))
        self.sleep.assert_not_called()
        self.cli.assert_not_called()

    def test_wait_reports_completed_failure_without_retry(self):
        self.api.return_value = self.run_response(conclusion="failure")
        with self.assertRaisesRegex(github.ReleaseError, "concluded with failure") as error:
            self.wait_for_run()
        self.assertIn(self.run_url, str(error.exception))
        self.api.assert_called_once()
        self.cli.assert_not_called()

    def test_wait_tolerates_initial_run_visibility_delay(self):
        self.api.side_effect = (github.ReleaseError("gh: Not Found (HTTP 404)"), self.run_response())
        self.wait_for_run()
        self.assertEqual([call.args for call in self.api.call_args_list], [(self.endpoint,)] * 2)
        self.sleep.assert_called_once()

    def test_wait_tolerates_initial_pending_provenance_for_the_dispatched_id(self):
        self.api.side_effect = (
            self.run_response(status="queued", conclusion=None, display_title="Wardr live release smoke"),
            self.run_response(),
        )
        self.wait_for_run()
        self.assertEqual([call.args for call in self.api.call_args_list], [(self.endpoint,)] * 2)
        self.sleep.assert_called_once()

    def test_wait_rejects_provenance_changes_after_verification(self):
        self.api.side_effect = (
            self.run_response(status="queued", conclusion=None),
            self.run_response(status="in_progress", conclusion=None, head_branch="main"),
        )
        with self.assertRaisesRegex(github.ReleaseError, "does not match"):
            self.wait_for_run()
        self.sleep.assert_called_once()

    def test_wait_fails_if_a_previously_visible_run_disappears(self):
        self.api.side_effect = (
            self.run_response(status="queued", conclusion=None),
            github.ReleaseError("gh: Not Found (HTTP 404)"),
        )
        with self.assertRaisesRegex(github.ReleaseError, "Could not read the live release run"):
            self.wait_for_run()
        self.assertEqual(self.api.call_count, 2)
        self.sleep.assert_called_once()

    def test_retry_ignores_stale_completed_results_until_a_new_attempt(self):
        self.api.side_effect = (
            self.run_response(run_attempt=3, conclusion="failure"),
            self.run_response(run_attempt=3),
            self.run_response(run_attempt=2, conclusion="failure"),
            self.run_response(run_attempt=4, status="in_progress", conclusion=None),
            self.run_response(run_attempt=4),
        )
        self.wait_for_run(retry_failed=True)
        self.assertEqual([call.args for call in self.api.call_args_list], [(self.endpoint,)] * 5)
        self.assertEqual(
            self.cli.call_args.args,
            ("run", "rerun", str(self.run_id), "--failed", "--repo", "github.com/Luminary-Analytics/wardr"),
        )
        self.assertEqual(self.cli.call_count, 1)

    def test_retry_reports_failure_on_the_new_attempt(self):
        self.api.side_effect = (
            self.run_response(run_attempt=3, conclusion="failure"),
            self.run_response(run_attempt=4, conclusion="timed_out"),
        )
        with self.assertRaisesRegex(github.ReleaseError, "timed_out"):
            self.wait_for_run(retry_failed=True)
        self.assertEqual(self.api.call_count, 2)
        self.cli.assert_called_once()


if __name__ == "__main__":
    unittest.main()
