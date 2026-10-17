# CI tool pins

This module pins the external binaries CI builds. Nothing imports it, and it
is not part of the main module's build.

A tool is added by importing its command package in `tools.go` (under the
`tools` build tag) and running `go get`. CI then builds it from here:

```bash
(cd .github/tools && GOWORK=off go build -o "$RUNNER_TEMP/bin/nfpm" github.com/goreleaser/nfpm/v2/cmd/nfpm)
```

The version is recorded in this module's `go.mod` and `go.sum` and verified
on download. To change it, run `go get github.com/goreleaser/nfpm/v2@<version>`
here, then `go mod tidy`.
