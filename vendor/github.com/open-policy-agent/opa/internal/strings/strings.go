// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package strings contains helpers to perform string manipulation
package strings

import (
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/internal/lcss"
)

// TruncateFilePaths truncates the given file paths to conform to the given
// "ideal" width and returns the shortened paths by replacing the middle parts of paths
// with "...", ex: bundle1/.../a/b/policy.rego
func TruncateFilePaths(maxIdealWidth, maxWidth int, path ...string) (map[string]string, int) {
	var canShorten [][]byte

	for _, p := range path {
		canShorten = append(canShorten, []byte(getPathFromFirstSeparator(p)))
	}

	// Find the longest common path segment
	var lcs string
	if len(canShorten) > 1 {
		lcs = string(lcss.LongestCommonSubstring(canShorten...))
	} else {
		lcs = string(canShorten[0])
	}

	// Don't just swap in the full LCSS, trim it down to be the least amount of
	// characters to reach our "ideal" width boundary giving as much
	// detail as possible without going too long.
	diff := maxIdealWidth - (maxWidth - len(lcs) + 3)
	if diff > 0 {
		if diff > len(lcs) {
			lcs = ""
		} else {
			// Favor data on the right hand side of the path
			lcs = lcs[:len(lcs)-diff]
		}
	}

	result := map[string]string{}
	for _, p := range path {
		result[p] = p
	}

	longestLocation := maxWidth

	// Swap in "..." for the longest common path, but if it makes things better
	if len(lcs) > 3 {
		for path := range result {
			result[path] = strings.Replace(path, lcs, "...", 1)
		}

		// Drop the overall length down to match our substitution
		longestLocation = longestLocation - (len(lcs) - 3)
	}

	return result, longestLocation
}

func getPathFromFirstSeparator(path string) string {
	s := filepath.Dir(path)
	s = strings.TrimPrefix(s, string(filepath.Separator))
	firstSlash := strings.IndexRune(s, filepath.Separator)
	if firstSlash > 0 {
		return s[firstSlash+1:]
	}
	return s
}
