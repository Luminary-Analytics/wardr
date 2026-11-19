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
data for the browser demo. [Wardr demo](https://wardr.onrender.com/#demo)

## Operate and troubleshoot

| Situation | What to check |
| --- | --- |
| The dashboard denies access | Use the complete URL printed by the running Wardr process in the current browser tab. A restart issues a fresh launch token. |
| Checks or event sources show limited coverage | Review the evidence and coverage entries for the collector. Account permissions, missing OS tools, unavailable logs, or stale cached update data can explain gaps. |
| No repair option is offered | Run a fresh scan and review the finding. The checklist offers automatic repair only for eligible SSH permission failures on macOS and Linux. |
| Software assessment has no matches | Confirm that the CycloneDX data contains versioned package identifiers and that the supplied OSV records cover those packages. Review unassessed entries in the assessment summary. |
| The local model is unavailable | Run `wardr model status` and check that Ollama is running locally and the pinned model is ready. The deterministic remediation plan is available independently. |

To monitor a server continuously, run `wardr watch` under the account you
want to observe with your existing process supervisor. It emits each new event
as JSON Lines on standard output and coverage updates on standard error.
Dashboard mode also monitors while the process is running. It allows a
separate poll interval through `wardr serve --interval <seconds>`.

For offline use, provide the CycloneDX inventory and OSV advisory records
as local files. If you want optional AI review, run `wardr model pull` while
connected, confirm readiness with `wardr model status`, and then start
`wardr serve --offline`. Ollama manages the model files and can be configured
to disable its cloud features. [Ollama offline settings](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features)

- `wardr scan --format json` exports a device scan.
- `wardr exposure` lists the current local socket inventory as JSON.
- `wardr assess --sbom inventory.json --advisories advisories.json` stores
  assessment results for the selected state directory.
- `wardr plan --format html` builds an exportable remediation plan.
- `wardr advisories --refresh` explicitly downloads a fresh CISA catalog.

## Tests and packaging

```console
python -m unittest discover -s tests -v
uv build
```

Unit tests cover dashboard access, posture parsing and SSH repair safety,
socket-table interpretation, inventory matching, hunting rules, and the
local-model interface. The native GitHub Actions job uses Python 3.11 on
Ubuntu, macOS, and Windows. It also exercises the CLI collectors and plan
export, builds a wheel and source archive, installs the wheel, and checks
the installed entry point. Full collector coverage still depends on the
host and account behind the test. [CI workflow](../.github/workflows/checks.yml)

Setuptools packages the Python modules and dashboard assets. The wheel is
platform-independent Python with platform-specific behavior selected at
runtime. The product version lives in [pyproject.toml](../pyproject.toml).
Blender is only needed to edit or re-render the supplied brand assets.

## Release and website handoff

1. Confirm the intended version in `pyproject.toml` and check the native CI
   results. Build the wheel and source archive from the intended software revision.
2. Prepare the GitHub release with the wheel and archive from `dist/`.
   Use that same software checkout and artifacts to build the company site.
3. In the site checkout, run its release build and validation. It stages the
   downloads, SHA-256 checksums, versioned release manifest, and optional
   signature. Publish the validated site files through the site's Render
   Blueprint. [Company site repository](https://github.com/Luminary-Analytics/wardr-site)
4. On the public site, verify that the download points to the intended
   wheel and that the published checksum agrees with the release artifact.
   For signed releases, verify the manifest and artifact with `wardr verify-release`
   and a separately trusted Ed25519 public key. [Wardr homepage](https://wardr.onrender.com/)

Keep private signing keys outside both repositories. SHA-256 checksums allow
download integrity checks. An Ed25519 signature verifies release provenance
when the verifier already trusts the public key. The
[security policy](../SECURITY.md) covers vulnerability reporting and release
integrity.
