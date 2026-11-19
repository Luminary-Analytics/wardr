"""Exercise release integrity gates without contacting GitHub."""

from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile


SPEC = spec_from_file_location(
    "wardr_release_github", Path(__file__).resolve().parents[1] / "packaging/release_github.py",
)
github = module_from_spec(SPEC)
SPEC.loader.exec_module(github)

VERSION = "0.3.4"
COMMIT = "a" * 40
SIGNING_TAG = "vwardrsign-0_3_4"


def digest(data):
    return f"sha256:{sha256(data).hexdigest()}"


class VerifiedArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        groups = github._installer_groups(VERSION)
        self.runs = dict(zip(groups, (11, 12, 13)))
        self.artifacts = {}
        self.contents = {}
        self.archives = {}
        for workflow, names in groups.items():
            run_id = self.runs[workflow]
            self.artifacts[run_id] = []
            for name, members in names.items():
                entries = {member: member.encode() for member in members}
                self.contents.update(entries)
                artifact = {"id": len(self.archives) + 100, "name": name, "expired": False}
                self.artifacts[run_id].append(artifact)
                self.archive(artifact, entries)
        api = patch.object(github, "_api", side_effect=self.api)
        cli = patch.object(github, "_gh", side_effect=self.cli)
        api.start()
        cli.start()
        self.addCleanup(api.stop)
        self.addCleanup(cli.stop)

    def archive(self, artifact, entries):
        buffer = BytesIO()
        with ZipFile(buffer, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        content = buffer.getvalue()
        self.archives[artifact["id"]] = content
        artifact.update(size_in_bytes=len(content), digest=digest(content))

    def api(self, endpoint, *options, **kwargs):
        path = urlsplit(endpoint).path
        run_id = int(path.split("/runs/")[1].split("/")[0])
        if path.endswith("/artifacts"):
            return [{"artifacts": self.artifacts[run_id]}]
        workflow = next(name for name, value in self.runs.items() if value == run_id)
        return {
            "id": run_id, "path": f".github/workflows/{workflow}", "head_branch": SIGNING_TAG,
            "head_sha": COMMIT, "event": "push", "status": "completed", "conclusion": "success",
        }

    def cli(self, *arguments, stdout, **kwargs):
        self.assertEqual(arguments[:3], ("api", "--hostname", "github.com"))
        self.assertTrue(arguments[3].endswith("/zip"))
        stdout.write(self.archives[int(arguments[3].split("/")[-2])])

    def test_installer_download_is_repeatable(self):
        for _ in range(2):
            files = github.fetch_installers(VERSION, self.runs, self.root / "installers")
            self.assertEqual({name: path.read_bytes() for name, path in files.items()}, self.contents)

    def test_rejects_wrong_archive_digest_before_writing_installers(self):
        self.artifacts[11][0]["digest"] = "sha256:" + "f" * 64
        destination = self.root / "installers"
        with self.assertRaisesRegex(github.ReleaseError, "does not match its GitHub ZIP size and digest"):
            github.fetch_installers(VERSION, self.runs, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_rejects_traversal_even_with_matching_archive_digest(self):
        names = github._installer_groups(VERSION)["wardr-windows-sign.yml"]
        (members,) = names.values()
        entries = {name: self.contents[name] for name in members}
        entries["../outside.txt"] = b"Invalid archive fixture"
        self.archive(self.artifacts[11][0], entries)
        destination = self.root / "installers"
        with self.assertRaisesRegex(github.ReleaseError, "Unexpected or duplicate ZIP entries"):
            github.fetch_installers(VERSION, self.runs, destination)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.root / "outside.txt").exists())


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
        results = (None, self.release, self.release)
        with patch.object(github, "_find_release", side_effect=results), patch.object(github, "_gh") as cli:
            self.assertTrue(github.stage_draft(VERSION, self.files))
        cli.assert_called_once()
        self.assertIn("--prerelease", cli.call_args.args)
        self.assertIn("--verify-tag", cli.call_args.args)

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


if __name__ == "__main__":
    unittest.main()
