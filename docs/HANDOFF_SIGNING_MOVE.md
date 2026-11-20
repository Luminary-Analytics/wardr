# Handoff: moving Wardr's installer signing into this repository

Status: to do. Written November 20, 2026, for the Wardr maintainer session that
takes this on. **Start from the draft pull request
[#2](https://github.com/Luminary-Analytics/wardr/pull/2)**, which implements the
design below (the workflows, the runner change, its tests and docs). It has not
run against GitHub or the signing services, and it isn't merged.

## The decision

On November 20, 2026 the owner decided that Wardr and Lumi keep completely
separate signing workflows, while signing with the same Luminary Analytics
identities:

> "We need to make sure Wardr and Lumi have separate workflows, they should use
> the same Organization for signing everything but completely separate and
> disparate workflows for obvious reasons"

Same organization means the same Apple Developer ID (Developer ID Application:
BY LUMINARY ANALYTICS) and the same Microsoft Artifact Signing account and
certificate profile. Separate workflows means Wardr's installers are built,
signed and verified by workflows in this repository, from this repository's
code, in this repository's own `release` environment.

## How it works today

- `packaging/release.py` and `packaging/release_github.py` hard-code
  `Luminary-Analytics/resonant-client` (Lumi's private repository) as the
  signing repository, and `release.py` takes `--signing-repo`.
- `prepare_request` commits the sealed wheel and `packaging/wardr-release/request.json`
  (version, reviewed commit, wheel SHA-256) to that repository's `main`, and
  pushes a `vwardrsign-X_Y_Z` tag.
- The tag starts three workflows there: `wardr-windows-sign.yml`,
  `wardr-macos-sign.yml` and `wardr-linux-build.yml`. Their signing jobs use
  Lumi's `release` environment, so Wardr's signing depends on Lumi's workflow
  rules and tests.
- `wait_signing` waits for those three runs, and `fetch_installers` downloads
  their private Actions artifacts (the five installers and the Windows
  `authenticode.json` proof).
- The Ed25519 Wardr release key never leaves the maintainer's Mac. It signs the
  site's `release.json`, not the wheel, and that doesn't change.

## The agreed design

- **Trigger:** a `sign-vX.Y.Z` tag on `main`, pushed by the release runner. Every
  job also checks `github.repository == 'Luminary-Analytics/wardr'`, that the
  tag's commit is on `main`, and that the reviewed commit comes before it.
- **The wheel:** the runner puts the sealed wheel on the draft GitHub release
  `vX.Y.Z` (create it with `gh release create vX.Y.Z --draft --prerelease
  --target <reviewed commit>`; the `vX.Y.Z` tag itself is pushed at
  publication, as now). It then commits `request.json` to `main` and pushes the
  signing tag. Each workflow downloads the wheel from the draft and checks its
  SHA-256 against the committed request.
- **Nothing pre-release is a public Actions artifact.** This repository is
  public, and anyone signed in to GitHub can download a run's artifacts. Signed
  installers and every intermediate (payloads, unsigned Setup, unsigned disk
  images) move between jobs through the draft release only. A suggested shape:
  name a file on its way to the next job `staging-...`, record its asset ID and
  SHA-256 as a job output, delete it once the next job has it, and give a
  verified installer its final name only after the clean-runner checks pass.
  The runner then fetches the installers from the draft and removes any
  `staging-...` files and the Windows proof before it uploads the rest of the
  release.
- **Permissions:** the narrowest that work. Reading a draft release needs write
  access, so jobs that touch the draft need `contents: write`; that is accepted
  for the secret-free preparation jobs too. Only the Windows signing job asks
  for an OIDC token (`id-token: write`). No `pull_request_target`, and no
  secrets in any job a pull request can start.
- **Environment:** `release` in this repository, deployment rule `sign-v*`
  (tags), the owner as required reviewer. Only the signing jobs use it.
- **Tag ruleset:** only administrators create, move or delete `sign-v*` tags.
- **Windows signing** can use this repository's own
  `packaging/windows/Authenticode.ps1` (its Azure mode takes the Artifact
  Signing dlib and metadata file) after `azure/login` with the job's OIDC token.
  The dlib comes from Microsoft's NuGet package
  `Microsoft.ArtifactSigning.Client`, pinned by version and SHA-256 and
  verified before it is extracted.
- **macOS signing** keeps today's steps (temporary keychain, Developer ID
  signing, notarization with an App Store Connect API key, stapling) and
  today's clean-runner verification.

## Owner setup checklist

Do these in GitHub settings for `Luminary-Analytics/wardr`, and in Microsoft
Entra ID. Names only; values never go in this repository.

1. **Environment.** Settings › Environments › New environment `release`.
   Deployment branches and tags: selected branches and tags, add the tag rule
   `sign-v*`. Required reviewers: the owner.
2. **Tag ruleset.** Settings › Rules › Rulesets › New tag ruleset targeting
   `sign-v*`: restrict creations, updates and deletions, with repository
   administrators as the only bypass.
3. **Variables** on the `release` environment, the same names and values as
   the variables of resonant-client's `release` environment. Read them there
   with `gh api repos/Luminary-Analytics/resonant-client/environments/release/variables`,
   then set each with `gh variable set <NAME> --env release --repo Luminary-Analytics/wardr`:
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `ARTIFACT_SIGNING_ENDPOINT`,
   `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_PROFILE`,
   `WINDOWS_SIGN_EXPECTED_SUBJECT`.
4. **Secrets** on the `release` environment. GitHub never shows a secret's
   value again, so take each from the password manager:
   `MACOS_SIGN_IDENTITY`, `MACOS_SIGN_P12_BASE64`, `MACOS_SIGN_P12_PASSWORD`,
   `APPLE_API_KEY_BASE64`, `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`.
5. **Azure federated credential** on the existing app registration
   `lumi-release-signing` (Certificates & secrets › Federated credentials › Add):
   scenario GitHub Actions, organization `Luminary-Analytics`, repository
   `wardr`, entity type Environment, environment `release`, name
   `wardr-release`. That gives issuer `https://token.actions.githubusercontent.com`,
   subject `repo:Luminary-Analytics/wardr:environment:release` and audience
   `api://AzureADTokenExchange`. The app already holds the Artifact Signing
   Certificate Profile Signer role, so no new role is needed.
6. **Branch rules.** The runner pushes the signing request commit to `main`, so
   any rule on `main` must still let the releasing maintainer push it.

## Work to do in this repository

Draft #2 does items 1 to 3; review it, finish it and run it.

1. Add the three workflows, for example `release-windows.yml`,
   `release-macos.yml` and `release-linux.yml`, ported from the
   `wardr-*` workflows described above, with the design above.
2. Change the runner:
   - `release_github.py`: wait for the new workflows in this repository on the
     `sign-vX.Y.Z` tag; fetch the installers and proof from the draft release
     instead of artifacts; let `stage_draft` create the draft with `--target`
     before its tag exists; add a step that removes staging files and the
     proof before publication.
   - `release.py`: drop `--signing-repo`; stage the wheel on the draft, commit
     `request.json` and push the signing tag in this repository.
   - Update `tests/test_release_automation.py`, and add tests for the request
     validator.
3. Update `packaging/README.md` and `docs/DEVELOPMENT.md` ("Publish a
   release"), which still describe the private signing repository.
4. Get the owner's OK before the first signing run. It needs the setup above
   and a release, or a test version, to sign.

## After Wardr signs on its own (Lumi's side)

- A resonant-client pull request deletes `wardr-windows-sign.yml`,
  `wardr-macos-sign.yml` and `wardr-linux-build.yml` and the
  `packaging/wardr-release/` request folder, and updates
  `tests/test_release_supply_chain.py`, `AGENTS.md` and the release docs, which
  currently name Wardr's workflows as the one exception to "only release.yml
  uses the release environment".
- The owner then narrows resonant-client's `release` environment tag rule from
  `v*` to `v*.*.*`, so no `vwardrsign-*` tag can reach it again.
