// Copyright 2019 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package url contains helpers for dealing with file paths and URLs.
package url

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
)

var goos = runtime.GOOS

// Clean returns a cleaned file path that may or may not be a URL.
func Clean(path string) (string, error) {

	if strings.Contains(path, "://") {

		url, err := url.Parse(path)
		if err != nil {
			return "", err
		}

		if url.Scheme != "file" {
			return "", fmt.Errorf("unsupported URL scheme: %v", path)
		}

		path = url.Path

		// Trim leading slash on Windows if present. The url.Path field returned
		// by url.Parse has leading slash that causes CreateFile() calls to fail
		// on Windows. See https://github.com/golang/go/issues/6027 for details.
		if goos == "windows" && len(path) >= 1 && path[0] == '/' {
			path = path[1:]
		}
	}

	return path, nil
}
