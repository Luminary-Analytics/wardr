# Release signing

Wardr's release installers are built, signed and verified in this repository by
three workflows that a `sign-vX.Y.Z` tag on `main` starts. Luminary Analytics
signs them with the same identities as its other products: its Apple Developer
ID and its Microsoft Artifact Signing account. The workflows are Wardr's own;
nothing is built or signed in another repository.

| Workflow | What it does | Signing credentials |
| --- | --- | --- |
| [release-windows.yml](../../.github/workflows/release-windows.yml) | Builds and smoke-tests Setup, signs it with Authenticode (`packaging/windows/Authenticode.ps1` and Microsoft's pinned Artifact Signing client), then checks the signature and installs, updates and uninstalls on a clean runner | The `sign` job only: an Azure sign-in through GitHub's OIDC token |
| [release-macos.yml](../../.github/workflows/release-macos.yml) | Stages the offline payload, builds Wardr.app and the disk image, signs with the Developer ID, notarizes and staples, then checks Gatekeeper, the tickets and the native updater on a clean runner | The `sign` jobs only: the Apple secrets |
| [release-linux.yml](../../.github/workflows/release-linux.yml) | Builds the `.run` installers and checks an offline install and an in-app update | None |

## How a release reaches them

The release runner ([packaging/release.py](../release.py)) does this; nobody
types the tag by hand.

1. It seals the wheel from the reviewed commit and puts it on the draft GitHub
   release `vX.Y.Z`, which only people with write access can see.
2. It commits `packaging/signing/request.json` (the version, the reviewed commit
   and the wheel's SHA-256) to `main`, and pushes `sign-vX.Y.Z` on that commit.
   [read_request.py](read_request.py) checks the request names its own tag.
3. Each workflow checks the tag is on `main` and the reviewed commit comes
   before it, downloads the wheel from the draft and checks its SHA-256, and
   builds from the reviewed commit's source.
4. Files move between jobs through the draft release
   ([release_draft.py](release_draft.py)): a file on its way to the next job is
   named `staging-...` and is deleted once used, and each download is checked
   against the SHA-256 the previous job recorded. A verified installer gets its
   final name only after the clean-runner checks pass. The runner fetches the
   five installers and the Windows signing proof, then removes the proof and
   any staging files before it publishes.

This repository is public, and anyone signed in to GitHub can download a run's
Actions artifacts, so nothing that exists before a release is published is kept
as an artifact.

## Who can start a signing run

- The workflows start only on a `sign-v*.*.*` tag push, and every job checks
  `github.repository == 'Luminary-Analytics/wardr'`. Pull requests, including
  ones from forks, never start them, and no workflow here uses
  `pull_request_target`.
- The signing jobs run in the `release` environment. It admits only `sign-v*`
  tags, and the owner approves each run as its required reviewer. Its secrets
  and the Azure sign-in exist only there.
- A tag ruleset lets only administrators create, move or delete `sign-v*` tags.
- Jobs have only the permissions they use. They need `contents: write`
  because reading a draft release needs write access. Only the Windows `sign`
  job may ask for an OIDC token (`id-token: write`).

## The `release` environment

Settings › Environments › `release`:

- Deployment branches and tags: selected, the tag pattern `sign-v*` only.
- Required reviewers: the owner.
- Secrets, the same names Luminary uses elsewhere: `MACOS_SIGN_IDENTITY`,
  `MACOS_SIGN_P12_BASE64`, `MACOS_SIGN_P12_PASSWORD`, `APPLE_API_KEY_BASE64`,
  `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID`.
- Variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `ARTIFACT_SIGNING_ENDPOINT`,
  `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_PROFILE`,
  `WINDOWS_SIGN_EXPECTED_SUBJECT`.

In Microsoft Entra ID, the app registration that signs (`lumi-release-signing`)
has a federated credential with issuer `https://token.actions.githubusercontent.com`,
subject `repo:Luminary-Analytics/wardr:environment:release` and audience
`api://AzureADTokenExchange`, and its service principal has the **Artifact
Signing Certificate Profile Signer** role on the certificate profile.
