# Wardr Linux installer

Choose the `x64` download for `x86_64` or the `arm64` download for `aarch64`.
These installers bundle a Linux runtime, the Wardr wheel, and its dependencies.
The bundled runtime and dependencies target glibc 2.17 or newer. Use the Python
wheel on distributions that use musl, such as
Alpine. Verify the installer against the signed release manifest before
running it. [Wardr downloads](https://getwardr.com/#release) ·
[Bundled Python runtime requirements](https://github.com/astral-sh/python-build-standalone/blob/main/docs/running.rst#linux)

Run the installer as your regular user. It works without network access or
an existing Python installation. Replace `x64` with `arm64` for that download.

```sh
sh ./wardr-0.2.1-linux-x64.run
```

Open **Wardr** from the desktop applications menu or use the command printed
by the installer. Add `--no-desktop` to the installer command on a server.
The app and its writable virtual environment live under
`${XDG_DATA_HOME:-$HOME/.local/share}/wardr`. The installer adds a shortcut at
`~/.local/bin/wardr` if that path is available. Wardr keeps its scan history,
configuration, and events in its separate state directory. Use **Updates** in
the app for future signed releases.

## Build and test

Stage the payload on Linux using `packaging/build_payload.py`. This fetches the
canonical signed wheel from `getwardr.com` and downloads the matching Python
runtime and dependency wheels. Pass the staged directory to the Linux builder.

```sh
python packaging/build_payload.py --version 0.2.1 --output /tmp/wardr-payload
python packaging/linux/build.py --payload /tmp/wardr-payload --arch x64 --output dist
```

Use `ubuntu-24.04` for x64 and `ubuntu-24.04-arm` for arm64 when building in
GitHub Actions. After building, install the artifact as a regular user in a
fresh disposable home, ideally in a container with networking disabled.
Confirm the shortcut launches, the installed version matches, and
`wardr.updater.installation_problem()` returns `None` from the installed
Python environment. Repeating the same install should preserve Wardr's state
directory. [GitHub-hosted runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
