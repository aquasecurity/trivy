// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package version implements helper functions for the stored version.
package version

import (
	"context"
	"fmt"
	"runtime"

	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/version"
)

var versionPath = storage.MustParsePath("/system/version")

// Write the build version information into storage. This makes the
// version information available to the REPL and the HTTP server.
func Write(ctx context.Context, store storage.Store, txn storage.Transaction) error {

	if err := storage.MakeDir(ctx, store, txn, versionPath); err != nil {
		return err
	}

	return store.Write(ctx, txn, storage.AddOp, versionPath, map[string]interface{}{
		"version":         version.Version,
		"build_commit":    version.Vcs,
		"build_timestamp": version.Timestamp,
		"build_hostname":  version.Hostname,
	})
}

// UserAgent defines the current OPA instances User-Agent default header value.
var UserAgent = fmt.Sprintf("Open Policy Agent/%s (%s, %s)", version.Version, runtime.GOOS, runtime.GOARCH)
