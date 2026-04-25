# Copilot instructions for SiteBrush v2

## Project basics

- This repository is a Go module named `sitebrush` and currently targets Go 1.19.
- Keep default builds CLI/non-GUI only. The WebView GUI is optional and must be enabled explicitly with the `gui` build tag.
- Do not touch `vendor/` unless dependency changes are intentionally required.
- Run `gofmt` on modified Go files.

## Local toolchain

In the current agent environment, use the locally installed Go toolchain before running Go commands:

```sh
export PATH=/Users/azenkov/.copilot/session-state/59c7663d-092f-4d19-9d88-255626450d2a/files/go/bin:$PATH
```

## Validation commands

Default non-GUI validation:

```sh
go test ./...
go build ./...
go build -o sitebrush .
```

Optional GUI validation, only on platforms with WebView system dependencies installed:

```sh
go build -tags gui -o sitebrush-gui .
```

If the GUI build fails with missing WebView/C++ system headers or libraries, keep default non-GUI validation passing and document the platform dependency blocker in the work summary.

## Build script notes

`scripts/crosscompile.sh` builds non-GUI artifacts by default and attempts GUI artifacts with `-tags gui` where the target can compile. Publishing is opt-in:

```sh
PUBLISH=1 scripts/crosscompile.sh
```
