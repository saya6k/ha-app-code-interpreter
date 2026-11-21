# ha-app-code-interpreter

Source repo for the **Code Interpreter** Home Assistant app — stateful Python
code execution in hardened throwaway sandboxes, supplied to Assist
conversation agents over MCP (streamable HTTP).

Install it from the [saya6k/ha-apps](https://github.com/saya6k/ha-apps)
catalog. This repo carries the source, Dockerfile, and CI; the catalog carries
the metadata.

## Release flow

1. Merge to `main` — release-drafter updates the draft.
2. Publish the draft → `build.yml` pushes `ghcr.io/saya6k/app-code-interpreter:{ver}`.
3. The build dispatches to ha-apps, which opens a version-bump PR.

## Trademarks

The app icon and logo are the unmodified "Python Powered" badges published by
the Python Software Foundation. "Python" and the Python logos are trademarks or
registered trademarks of the Python Software Foundation. This app is an
independent community project and is not affiliated with or endorsed by the PSF.
