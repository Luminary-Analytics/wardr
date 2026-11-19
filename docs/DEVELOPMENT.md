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

Add `--plan` for a read-only preview. Rerun the same command to resume, and
add `--retry-failed` to retry failed cloud jobs. Keep the sealed artifacts and
saved progress in `dist/release/X.Y.Z` until the release checks finish. If the site
or update feed is still serving the previous release after the deploy check,
check the Render deploy log and rerun the same command after resolving it.

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
4. After Render verification, it runs the Windows live release smoke test and
   waits for a successful result. The baseline version comes from the signed
   prior feed saved in the release checkpoint. For the release after 0.2.2,
   the workflow uses the published 0.2.2 Windows Setup and upgrades it through
   the dashboard against the production feed. It also tests the new Setup and
   checks that the upgrade preserves settings and saved data.
   [Windows live release workflow](../.github/workflows/windows-live-release.yml)

If the Windows check fails, the command reports a verification error after
the target is publicly live. Rerun the same command to resume the recorded
Actions run. Add `--retry-failed` to rerun failed Windows verification.

Keep the Wardr release key local and outside the repositories. Keep platform
signing credentials in the protected private release environment. Installed
Wardr clients verify the signed feed on getwardr.com using PyCA cryptography.
Wardr 0.2.0 users can install the current wheel manually to get in-app
updates. [Security policy](../SECURITY.md)
