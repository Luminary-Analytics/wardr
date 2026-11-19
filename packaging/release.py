"""Build and publish one Wardr Community release from a maintainer Mac."""

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory, mkdtemp
import tomllib
from zipfile import ZipFile

from release_github import ReleaseError, fetch_installers, promote, stage_draft, wait_checks, wait_signing


ROOT = Path(__file__).resolve().parents[1]
SOFTWARE = "Luminary-Analytics/wardr"
SITE = "Luminary-Analytics/wardr-site"
SIGNING = "Luminary-Analytics/resonant-client"
REQUEST = Path("packaging/wardr-release")
PUBLIC_KEY = Path("wardr/keys/release.pem")
APPLE_TEAM = "9M6C299C9U"
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
COMMIT = re.compile(r"[a-f0-9]{40}")
SHA256 = re.compile(r"[a-f0-9]{64}")


def run(*args, cwd=None, capture=False, timeout=300):
    return subprocess.run(
        [str(arg) for arg in args], cwd=cwd, check=True, timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


def git(repo, *args, capture=False, timeout=300):
    return run("git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
               "-C", repo, *args, capture=capture, timeout=timeout)


def git_text(repo, *args):
    return git(repo, *args, capture=True).decode().strip()


def log(message):
    print(message, flush=True)


def version_key(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ReleaseError("Expected a canonical major.minor.patch release version.")
    return tuple(map(int, version.split(".")))


def wheel_name(version):
    return f"wardr-{version}-py3-none-any.whl"


def installer_names(version):
    return [
        f"wardr-{version}-{platform}"
        for platform in ("windows-x64-setup.exe", "macos-arm64.dmg", "macos-x64.dmg", "linux-x64.run", "linux-arm64.run")
    ]


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ReleaseError(f"Expected a regular release file at {path}.")
    with path.open("rb") as handle:
        return file_digest(handle, "sha256").hexdigest()


def verify_files(directory, names, expected):
    if not isinstance(expected, dict) or set(expected) != set(names):
        raise ReleaseError(f"Invalid recorded release files for {directory}.")
    for name in names:
        if digest(directory / name) != expected[name]:
            raise ReleaseError(f"{name} differs from its recorded release digest.")


def save_state(stage, state):
    target = stage / "state.json"
    temporary = stage / "state.json.tmp"
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def require_repo(path, repository):
    if Path(git_text(path, "rev-parse", "--show-toplevel")).resolve() != path.resolve():
        raise ReleaseError(f"Use the root of the {repository} checkout.")
    origin = git_text(path, "remote", "get-url", "origin").removesuffix(".git").casefold()
    if origin not in {f"https://github.com/{repository.casefold()}", f"git@github.com:{repository.casefold()}",
                      f"ssh://git@github.com/{repository.casefold()}"}:
        raise ReleaseError(f"The origin of {path} must be {repository}.")


def remote_ref(repo, ref):
    refs = {}
    for line in git_text(repo, "ls-remote", "origin", ref, f"{ref}^{{}}").splitlines():
        git_sha, name = line.split()
        refs[name] = git_sha
    return refs.get(f"{ref}^{{}}") or refs.get(ref)


def require_main_ancestor(repo, commit):
    main = fetch_main(repo)
    try:
        git(repo, "merge-base", "--is-ancestor", commit, main)
    except subprocess.CalledProcessError as exc:
        raise ReleaseError(f"{commit} must be on the published Wardr main branch.") from exc


def fetch_main(repo):
    main = remote_ref(repo, "refs/heads/main")
    if not main or not COMMIT.fullmatch(main):
        raise ReleaseError(f"Could not determine the current main commit for {repo}.")
    git(repo, "fetch", "--no-tags", "--no-write-fetch-head", "origin", main)
    return main


@contextmanager
def release_lock(stage):
    stage.mkdir(parents=True, mode=0o700, exist_ok=True)
    if stage.is_symlink() or not stage.is_dir():
        raise ReleaseError("Use a regular release staging directory.")
    with (stage / ".lock").open("ab") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReleaseError("A process is already releasing this version.") from exc
        yield


@contextmanager
def main_worktree(repo, work):
    git(repo, "worktree", "add", "--detach", work, fetch_main(repo))
    try:
        yield work
    finally:
        if not git_text(work, "status", "--porcelain"):
            git(repo, "worktree", "remove", work)
        else:
            log(f"Kept the unfinished release worktree at {work}.")


def extract_source(commit, directory):
    directory.mkdir()
    with TemporaryDirectory(prefix="wardr-source-") as temporary:
        archive = Path(temporary) / "source.tar"
        git(ROOT, "archive", "--format=tar", "-o", archive, commit)
        with tarfile.open(archive) as tar:
            tar.extractall(directory, filter="data")


def verify_key(commit, signing_key):
    key = git(ROOT, "show", f"{commit}:{PUBLIC_KEY.as_posix()}", capture=True)
    if run("openssl", "pkey", "-in", signing_key, "-pubout", capture=True, timeout=15) != key:
        raise ReleaseError("The local signing key does not match the key embedded in the pinned source.")
    return key


def prepare_packages(stage, source, version, key, state):
    packages = stage / "packages"
    names = [wheel_name(version), f"wardr-{version}.tar.gz"]
    if "packages" in state:
        verify_files(packages, names, state["packages"])
    else:
        packages.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix="wardr-build-", dir=stage) as temporary:
            run("uv", "build", "--out-dir", temporary, source, timeout=900)
            built = Path(temporary)
            if {path.name for path in built.iterdir()} - {".gitignore"} != set(names):
                raise ReleaseError("Expected exactly one versioned wheel and one source archive from the reviewed commit.")
            hashes = {name: digest(built / name) for name in names}
            with ZipFile(built / names[0]) as wheel:
                if wheel.read(PUBLIC_KEY.as_posix()) != key:
                    raise ReleaseError("The built wheel has the wrong release verification key.")
            for name in names:
                (built / name).replace(packages / name)
            state["packages"] = hashes
            save_state(stage, state)
    return packages


def live_metadata(path):
    return run("curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--max-time", "25",
               "--max-filesize", "131072", f"https://getwardr.com{path}", capture=True, timeout=30)


def check_candidate_upgrade(site, stage, source, wheel, state, key):
    main = fetch_main(site)
    manifest = git(site, "show", f"{main}:public/releases/latest.json", capture=True)
    prior = json.loads(manifest)
    prior_version = prior["version"]
    comparison = version_key(prior_version)
    if (prior.get("schema_version"), prior.get("channel"), prior.get("signature")) != (
        1, "community", f"/releases/{prior_version}/release.json.sig",
    ):
        raise ReleaseError("The current site feed has an unexpected channel or signature path.")
    signature = git(site, "show", f"{main}:public{prior['signature']}", capture=True)
    previous_feed = {"version": prior_version, "manifest_sha256": sha256(manifest).hexdigest()}
    with TemporaryDirectory(prefix="wardr-upgrade-") as temporary:
        directory = Path(temporary)
        files = {"release.json": manifest, "release.json.sig": signature, "wardr-release.pem": key}
        for name, content in files.items():
            (directory / name).write_bytes(content)
        run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", directory / "wardr-release.pem",
            "-in", directory / "release.json", "-sigfile", directory / "release.json.sig", timeout=15)
        if prior_version == state["version"] and state.get("upgrade_verified"):
            return  # Publication may already have completed before the previous invocation stopped.
        if comparison >= version_key(state["version"]):
            raise ReleaseError("Use a version newer than the published application feed.")
        if live_metadata("/releases/latest.json") != manifest or live_metadata(prior["signature"]) != signature:
            raise ReleaseError("The live update feed differs from the site main branch. Let the prior deployment finish.")
        if state.get("upgrade_verified") == previous_feed:
            return
        baseline_name = wheel_name(prior_version)
        artifact, = (item for item in prior["artifacts"] if item["name"] == baseline_name)
        baseline = git(site, "show", f"{main}:public/downloads/{baseline_name}", capture=True)
        if len(baseline) != artifact["bytes"] or sha256(baseline).hexdigest() != artifact["sha256"]:
            raise ReleaseError("The prior wheel differs from the current signed release manifest.")
        previous_wheel = directory / baseline_name
        previous_wheel.write_bytes(baseline)
        log(f"Testing an in-place update from {prior_version} to the exact candidate wheel.")
        run("uv", "run", "--no-project", "--python", sys.executable, "--with", "cryptography==50.0.2", "python",
            source / "tests/smoke_update.py", previous_wheel, "--candidate", wheel, timeout=600)
    state["upgrade_verified"] = previous_feed
    save_state(stage, state)


def prepare_request(repo, work, version, commit, wheel):
    tag = "vwardrsign-" + version.replace(".", "_")
    ref = f"refs/tags/{tag}"
    request = {"schema_version": 1, "version": version, "commit": commit, "wheel_sha256": digest(wheel)}
    existing = remote_ref(repo, ref)
    if existing:
        git(repo, "fetch", "--no-tags", "--no-write-fetch-head", "origin", existing)
        current = json.loads(git(repo, "show", f"{existing}:{REQUEST}/request.json", capture=True))
        tagged_wheel = git(repo, "show", f"{existing}:{REQUEST}/{wheel.name}", capture=True)
        if current != request or sha256(tagged_wheel).hexdigest() != request["wheel_sha256"]:
            raise ReleaseError(f"The protected signing tag {tag} already identifies a different request.")
        return tag, existing
    with main_worktree(repo, work) as checkout:
        for filename in ("wardr-windows-sign.yml", "wardr-macos-sign.yml", "wardr-linux-build.yml"):
            if not (checkout / ".github/workflows" / filename).is_file():
                raise ReleaseError(f"The signing repository is missing {filename}.")
        request_path = checkout / REQUEST
        if not (request_path / "read_request.py").is_file():
            raise ReleaseError("The signing repository is missing the Wardr request validator.")
        for previous in request_path.glob("wardr-*-py3-none-any.whl"):
            previous.unlink()
        shutil.copyfile(wheel, request_path / wheel.name)
        (request_path / "request.json").write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        git(checkout, "add", "--", REQUEST)
        git(checkout, "diff", "--cached", "--check")
        git(checkout, "commit", "-m", f"Authorize Wardr {version} installer builds")
        request_commit = git_text(checkout, "rev-parse", "HEAD")
        git(checkout, "push", "--atomic", "origin", "HEAD:refs/heads/main", f"HEAD:{ref}")
    return tag, request_commit


def collect_installers(signing, work, stage, version, wheel, state, args):
    folder = stage / "installers"
    names = [*installer_names(version), "authenticode.json"]
    if "installers" not in state:
        tag, request_commit = prepare_request(signing, work, version, state["commit"], wheel)
        log(f"Waiting for protected installer jobs on {tag}.")
        runs = wait_signing(tag, request_commit, args.timeout, retry_failed=args.retry_failed)
        with TemporaryDirectory(prefix="wardr-verified-", dir=stage) as temporary:
            fetch_installers(version, runs, Path(temporary))
            hashes = {name: digest(Path(temporary) / name) for name in names}
            folder.mkdir(exist_ok=True)
            for name in names:
                (Path(temporary) / name).replace(folder / name)
        state["installers"] = hashes
        state["signing_runs"] = runs
        save_state(stage, state)
    verify_files(folder, names, state["installers"])
    proof = json.loads((folder / "authenticode.json").read_text(encoding="utf-8-sig"))
    win_name = installer_names(version)[0]
    if (proof.get("File"), proof.get("Version"), proof.get("Commit"), proof.get("WheelSha256"), proof.get("Sha256")) != (
        win_name, version, state["commit"], digest(wheel), digest(folder / win_name),
    ) or "Luminary Analytics, LLC" not in proof.get("PublisherSubject", "") or not (
        proof.get("PublisherThumbprint") and proof.get("TimestampSubject")
    ):
        raise ReleaseError("The Windows verification proof does not match this installer and source.")
    return folder, proof["Sha256"]


def ensure_release_tag(version, commit):
    ref = f"refs/tags/v{version}"
    existing = remote_ref(ROOT, ref)
    if existing and existing != commit:
        raise ReleaseError(f"{ref} already identifies another commit.")
    if existing is None:
        git(ROOT, "push", "origin", f"{commit}:{ref}")


def publish(site, work, source, packages, installers, windows_sha, state, args):
    version = state["version"]
    shutil.copytree(packages, source / "dist")
    with main_worktree(site, work) as checkout:
        run(sys.executable, "-m", "scripts.check_site", "--output", "public", cwd=checkout)
        public = checkout / "public"
        snapshot = (public / "releases/latest.json").read_bytes()
        previous = json.loads(snapshot)["version"]
        if version_key(version) < version_key(previous):
            raise ReleaseError(f"The site already serves the newer {previous} release.")
        if previous != version and state["upgrade_verified"] != {
            "version": previous, "manifest_sha256": sha256(snapshot).hexdigest(),
        }:
            raise ReleaseError(f"The site's {previous} feed changed while the release was in progress.")
        base = [sys.executable, "-m", "scripts.build_site", "--software", source, "--version", version,
                "--output", public, "--signing-key", args.signing_key]
        run(*base, cwd=checkout)
        archive = public / "releases" / version
        assets = [
            packages / wheel_name(version), packages / f"wardr-{version}.tar.gz",
            *(installers / name for name in installer_names(version)),
            *(archive / name for name in ("release.json", "release.json.sig", "wardr-release.pem")),
            public / "downloads/SHA256SUMS",
        ]
        ensure_release_tag(version, state["commit"])
        draft = stage_draft(version, assets)
        with TemporaryDirectory(prefix="wardr-catalog-") as temporary:
            catalog = Path(temporary) / "catalog"
            arguments = ("--allow-draft",) if draft else ()
            run(sys.executable, "-m", "scripts.register_installers", "--version", version,
                "--installer-dir", installers, "--windows-verified-sha256", windows_sha,
                "--mac-team-id", APPLE_TEAM, "--signing-key", args.signing_key, "--public-key",
                source / PUBLIC_KEY, "--output", catalog, *arguments, cwd=checkout, timeout=300)
            run(*base, "--installer-manifest-dir", catalog, cwd=checkout)
        run(sys.executable, "-m", "scripts.check_site", "--output", public, cwd=checkout)
        if draft:
            promote(version, assets)
        git(checkout, "add", "--", "public")
        if git_text(checkout, "diff", "--cached", "--name-only"):
            git(checkout, "diff", "--cached", "--check")
            git(checkout, "commit", "-m", f"Publish Wardr {version} downloads and application updates")
            git(checkout, "push", "origin", "HEAD:refs/heads/main")
        run(sys.executable, "-m", "scripts.verify_live", "--output", public, "--version", version,
            "--attempts", "60", "--deadline", "900", cwd=checkout, timeout=960)


def release(args):
    version = args.version
    version_key(version)
    state_dir = ROOT / "dist" / "release" / version
    paths = ((ROOT, SOFTWARE), (args.site, SITE), (args.signing_repo, SIGNING))
    for path, repo in paths:
        require_repo(path, repo)
    state_file = state_dir / "state.json"
    state = json.loads(state_file.read_bytes()) if state_file.exists() else {}
    if not isinstance(state, dict):
        raise ReleaseError("The saved release state must be a JSON object.")
    commit = state.get("commit") or git_text(ROOT, "rev-parse", "HEAD")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit) or (
        state and (state.get("schema_version"), state.get("version")) != (1, version)
    ):
        raise ReleaseError("The saved release state does not match this request.")
    project = tomllib.loads(git_text(ROOT, "show", f"{commit}:pyproject.toml"))["project"]
    if project["version"] != version:
        raise ReleaseError(f"The reviewed commit declares {project['version']}. Set {version} on main before releasing.")
    if args.plan:
        log(f"Wardr {version} from {commit}.")
        log("Verify CI and the previous-version upgrade, build and sign five installers, verify the GitHub draft, "
            "then publish the GitHub release, website, and application update feed.")
        log(f"Local checkpoint directory {state_dir}")
        return
    if sys.platform != "darwin":
        raise ReleaseError("Run publication on a Mac with codesign and stapler to verify both submitted DMGs.")
    with release_lock(state_dir), TemporaryDirectory(prefix="wardr-release-") as temporary:
        # Reload while locked in case a different invocation finished between planning and locking.
        if state_file.exists() and json.loads(state_file.read_bytes()) != state:
            raise ReleaseError("The release checkpoint has changed. Run the same command again.")
        require_main_ancestor(ROOT, commit)
        key = verify_key(commit, args.signing_key)
        wait_checks(commit, args.timeout)
        if not state:
            state = {"schema_version": 1, "version": version, "commit": commit}
            save_state(state_dir, state)
        parent = Path(temporary)
        source = parent / "source"
        extract_source(commit, source)
        packages = prepare_packages(state_dir, source, version, key, state)
        wheel = packages / wheel_name(version)
        check_candidate_upgrade(args.site, state_dir, source, wheel, state, key)
        # Persistent parent keeps any failed, dirty worktrees available for diagnosis.
        worktrees = Path(mkdtemp(prefix="wardr-work-", dir=state_dir))
        installers, windows_sha = collect_installers(args.signing_repo, worktrees / "request",
                                                     state_dir, version, wheel, state, args)
        check_candidate_upgrade(args.site, state_dir, source, wheel, state, key)
        publish(args.site, worktrees / "site", source, packages, installers, windows_sha, state, args)
        worktrees.rmdir()
    log(f"Wardr {version} is live at https://getwardr.com/#release.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--site", type=lambda value: Path(value).expanduser().resolve(), required=True)
    parser.add_argument("--signing-repo", type=lambda value: Path(value).expanduser().resolve(), required=True)
    parser.add_argument("--signing-key", type=lambda value: Path(value).expanduser().resolve(), required=True)
    parser.add_argument("--timeout", type=int, default=5400, help="Seconds to wait for each group of CI jobs.")
    parser.add_argument("--plan", action="store_true", help="Show the pinned release plan without making changes.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry failed signing jobs for this exact request.")
    args = parser.parse_args()
    try:
        if args.timeout < 1:
            raise ReleaseError("--timeout must be positive.")
        release(args)
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Wardr release stopped. {exc}\nRun the same command to resume.\n")


if __name__ == "__main__":
    main()
