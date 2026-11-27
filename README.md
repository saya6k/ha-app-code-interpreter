# ha-app-code-interpreter

Source repo for the **Code Interpreter** Home Assistant app: a sandboxed
JavaScript runner (with Python for analysis) that Assist conversation agents
use over MCP (streamable HTTP) to read and control Home Assistant, analyze
data and exchange files, one script per call.

Install it from the [saya6k/ha-apps](https://github.com/saya6k/ha-apps)
catalog. This repo carries the source, Dockerfile, and CI; the catalog carries
the metadata.

## Release flow

1. Merge to `main` — release-drafter updates the draft.
2. Publish the draft → `build.yml` pushes `ghcr.io/saya6k/app-code-interpreter:{ver}`.
3. The build dispatches to ha-apps, which opens a version-bump PR.
