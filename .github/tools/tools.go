//go:build tools

// Package tools pins the external binaries CI builds. It is never imported;
// the build tag keeps it out of ordinary builds.
package tools

import (
	// nfpm: builds the release RPMs. Pinned here rather than
	// `go install ...@version` in a workflow, so the version is recorded in
	// this module's go.sum and verified on download.
	_ "github.com/goreleaser/nfpm/v2/cmd/nfpm"
)
