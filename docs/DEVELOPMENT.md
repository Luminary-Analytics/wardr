# Development and operations

## Run from source

Use Python 3.11 or newer. From the software checkout, run the application
or inspect its command options.

```console
python -m wardr
python -m wardr --help
python -m wardr serve --help
```

For development and smoke checks, select a separate state directory outside
your normal profile. The global `--state-dir` option goes before the
subcommand.

```console
python -m wardr --state-dir /path/to/disposable/wardr-state serve --no-browser --offline
```

The server prints its private dashboard URL. The CLI and dashboard collect data
from the machine and account running the process. The public site uses sample
data for the browser demo. [Wardr demo](https://getwardr.com/#demo)

## Operate and troubleshoot

| Situation | What to check |
| --- | --- |
| The dashboard denies access | Use the complete URL printed by the running Wardr process in the current browser tab. A restart issues a fresh launch token. |
| Checks or event sources show limited coverage | Review the evidence and coverage entries for the collector. Account permissions, missing OS tools, unavailable logs, or stale cached update data can explain gaps. |
| No repair option is offered | Run a fresh scan and review the finding. The checklist offers automatic repair only for eligible SSH permission failures on macOS and Linux. |
| Software assessment has no matches | Confirm that the CycloneDX data contains versioned package identifiers and that the supplied OSV records cover those packages. Review unassessed entries in the assessment summary. |
| The local model is unavailable | Run `wardr model status` and check that Ollama is running locally and the pinned model is ready. The deterministic remediation plan is available independently. |
| In-place updates are unavailable | Install a published wheel in a pipx or Python virtual environment. Confirm pip is available to Wardr's interpreter or uv is on `PATH`, and check that the dashboard is online. |
| The update requires manual installation | Download and verify the published wheel. Close Wardr and use your package manager to install the wheel and its dependencies into the same environment. |
| An update cannot replace the Windows launcher | Close other Wardr processes. Invoke the environment's Python interpreter directly with `-m wardr update` or run the dashboard with `-m wardr serve`. |
| Installation was interrupted or failed partway | Close every Wardr process. Download and verify the intended release wheel, reinstall it in the existing environment using its package manager, and confirm the new version in **Updates** after launch. For pipx, use `pipx install --force` with that wheel. |

To monitor a server continuously, run `wardr watch` under the account you
want to observe with your existing process supervisor. It emits each new event
as JSON Lines on standard output and coverage updates on standard error.
Dashboard mode also monitors while the process is running. It allows a
separate poll interval through `wardr serve --interval <seconds>`.
On Windows, invoke the installed environment's Python with
`-m wardr serve --no-browser` for a headless dashboard. This leaves the Wardr
launcher available for a future package replacement.

For offline use, provide the CycloneDX inventory and OSV advisory records
as local files. If you want optional AI review, run `wardr model pull` while
connected, confirm readiness with `wardr model status`, and then start
`wardr serve --offline`. That dashboard session disables public advisory and
Wardr update downloads. Ollama manages the model files and can be configured
to disable its cloud features. [Ollama offline settings](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features)

- `wardr scan --format json` exports a device scan.
- `wardr exposure` lists the current local socket inventory as JSON.
- `wardr assess --sbom inventory.json --advisories advisories.json` stores
  assessment results for the selected state directory.
- `wardr plan --format html` builds an exportable remediation plan.
- `wardr advisories --refresh` explicitly downloads a fresh CISA catalog.
- `wardr update --check` checks the signed release channel. `wardr update`
  checks and installs an eligible newer release. Both commands require
  network access. Restart any running Wardr process after an install.

## Tests and packaging

Use a development virtual environment for local builds and tests.

```console
python -m pip install -e .
python -m unittest discover -s tests -v
uv build
```

Unit tests cover dashboard access, posture parsing and SSH repair safety,
socket-table interpretation, inventory matching, hunting rules, and the
local-model interface. Release tests also exercise signature and artifact
verification and installation eligibility. The native GitHub Actions job uses
Python 3.11 on Ubuntu, macOS, and Windows. It exercises the CLI collectors and plan
export, builds a wheel and source archive, installs the wheel, and checks
the installed entry point. Full collector coverage still depends on the
host and account behind the test. [CI workflow](../.github/workflows/checks.yml)

Setuptools packages the Python modules and dashboard assets. The wheel is
platform-independent Python with platform-specific behavior selected at
runtime. The product version lives in [pyproject.toml](../pyproject.toml).
Blender is only needed to edit or re-render the supplied brand assets.

## Publish a release

Use a maintainer Mac with Python 3.11 or newer, uv, Git, GitHub CLI, OpenSSL 3
on `PATH`, and Xcode command-line tools for `codesign` and `xcrun stapler`.
Authenticate GitHub CLI as a maintainer who can push to all three repositories,
create the protected signing tag, and dispatch workflows in the public Wardr
repository. Review the new version in
`pyproject.toml` and push the reviewed commit to the public Wardr repository's
`main` branch. From that commit, run the release with the company site checkout,
the existing private signing checkout, and the local Wardr release key.

```console
python3.11 packaging/release.py --version X.Y.Z --site ../Wardr-Site --signing-repo ../resonant-client --signing-key ~/.config/wardr-release/community-ed25519.pem
```

Add `--plan` for a read-only preview. Keep the sealed artifacts and saved
progress in `dist/release/X.Y.Z` until the release checks finish.

1. The runner seals the exact wheel and source archive from the reviewed
   commit. It tests an in-place upgrade from the currently published signed
   wheel to the candidate in a disposable installation and checks that saved
   state survives the restart.
2. It stages the request and sealed wheel on `main` and a release tag in the
   existing private signing repository. Its Windows, macOS, and Linux jobs
   build and test the native installers and run the platform signing steps.
3. It uploads the verified artifacts to a GitHub draft, checks the uploaded
   bytes, and stages and validates the company site with signed app and
   installer catalogs. It publishes with the existing GitHub prerelease
   status, pushes the site for Render to deploy, then verifies the live
   site, feed, and downloads over HTTPS.
   [Site release guide](https://github.com/Luminary-Analytics/wardr-site/blob/main/docs/release-and-hosting.md)
4. After Render verification, it runs live checks on Windows x64, Apple Silicon
   and Intel Macs, and Linux ARM64 and x64. Each job verifies the published
   installer against its signed catalog and checks a fresh target installation.
   Windows checks timestamped Authenticode. macOS checks Developer ID and
   notarization. Each job then installs the previous published version from the
   signed feed recorded in the release checkpoint, upgrades it through the
   live dashboard, and checks that settings and saved data survive the restart.
   [Native live release workflow](../.github/workflows/live-release.yml)

Keep the Wardr release key local and outside the repositories. Keep platform
signing credentials in the protected private release environment. Installed
Wardr clients verify the signed feed on getwardr.com using PyCA cryptography.
Wardr 0.2.0 users can install the current wheel manually to get in-app
updates. [Security policy](../SECURITY.md)

### Wait for GitHub run metadata

When Wardr 0.2.4 went live, GitHub first returned the generic title `Wardr live
release smoke` for the dispatched run. About five seconds later it returned
`Wardr live upgrade 0.2.3 to 0.2.4`. The original release command waited for
the metadata, tracked the same run, and finished successfully in one invocation.
[Wardr 0.2.4 live release run](https://github.com/Luminary-Analytics/wardr/actions/runs/44629265573)

Initial polling gives GitHub up to 30 seconds to expose the recorded run ID or
fill in metadata for that pending run. Before using a result, the runner verifies
the run ID, workflow, dispatch event, release tag, commit, and version pair. Let
the release command continue while it waits for metadata or for queued or
running jobs.

### Verify all five live checks

Open the Actions run URL printed by the release command. If the terminal is
closed, find the run ID in `live_release_run` in `dist/release/X.Y.Z/state.json`.
For 0.2.4, this command shows the release identity and all job conclusions.

```sh
gh run view 44629265573 --repo Luminary-Analytics/wardr \
  --json displayTitle,event,headBranch,headSha,status,conclusion,jobs \
  --jq '{displayTitle, event, headBranch, headSha, status, conclusion, jobs: [.jobs[] | {name, conclusion}]}'
```

- Match `displayTitle` to the previous and target versions, `headBranch` to the
  target tag such as `v0.2.4`, and `headSha` to `commit` in the release
  checkpoint. The event is `workflow_dispatch`.
- Confirm the run is `completed` with conclusion `success` and that all five
  jobs show `success` individually. Expect `Windows x64 / verify`, `macos x64`
  (Intel), `macos arm64` (Apple Silicon), `linux x64`, and `linux arm64`.
- In each job log, confirm the installer verification and the `Verified live
  Wardr 0.2.3 to 0.2.4 through https://getwardr.com with preserved local state`
  message for the expected version pair. The restart check covers the listening
  port, monitoring interval, saved assessment, advisory cache, report, and
  event history. A successful release command ends with `All five native live
  upgrade checks passed.`

After a partial retry, check the latest attempt for each job name across the
whole run. This command includes jobs that passed on earlier attempts. Replace
the run ID with the one from the release checkpoint.

```sh
gh api --paginate \
  'repos/Luminary-Analytics/wardr/actions/runs/44629265573/jobs?filter=all&per_page=100' \
  --jq '.jobs[] | [.name, .run_attempt, .status, .conclusion] | @tsv'
```

### Resume or retry a release

A manual resume is needed when the release command exits before it reports
success or is interrupted. While it is still running, let it handle Render
propagation, GitHub metadata delays, and active jobs. Use the same release version
and checkout paths, and preserve the checkpoint and sealed artifacts.

| What happened | How to continue |
| --- | --- |
| The command exited or was interrupted while an Actions run was queued, running, or already successful | Rerun the same release command. Once it revalidates the live site, it follows the saved `live_release_run`. |
| Render was still serving older files when live verification stopped | Check the Render deploy log, resolve any deploy problem, and rerun the same command once the target deployment is healthy. |
| A signing or live-check workflow failed | Inspect its job logs and resolve the cause. Rerun the release command with `--retry-failed` to retry eligible failed jobs on that same Actions run. |
| GitHub run metadata still did not match after the initial wait | Check that the run ID, tag, commit, and version pair match the intended release. Rerun the command once GitHub shows the expected metadata for that run. |

`--retry-failed` retries jobs from a recorded workflow that concluded with
`failure`, `startup_failure`, or `timed_out`, at most once per workflow run per
invocation. If dispatch was interrupted before `live_release_run` was saved,
check Actions for the target tag and version pair first. A release command
resumed without a recorded live run ID dispatches a new run.

The command reports live-check failures after publication. Retry the live
checks while the target is still the current signed version on getwardr.com.
If a newer version has gone live, use that release's own run to verify the live
feed.
