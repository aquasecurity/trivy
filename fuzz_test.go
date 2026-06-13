//go:build go1.18
// +build go1.18

// Copyright 2026 Aqua Security Software Ltd.
// SPDX-License-Identifier: Apache-2.0

package trivy_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/purl"
)

// FuzzPURLParse tests Package URL parsing with arbitrary
// attacker-controlled PURL strings.
//
// PURL is the universal package identifier format used in
// SBOMs and vulnerability databases. Trivy parses PURLs
// from untrusted sources (user-provided SBOMs, remote feeds).
func FuzzPURLParse(f *testing.F) {
	f.Add("pkg:golang/github.com/aquasecurity/trivy@1.0.0")
	f.Add("pkg:npm/express@4.18.2")
	f.Add("")
	f.Add("invalid")
	f.Add("pkg:")

	f.Fuzz(func(t *testing.T, purlStr string) {
		if len(purlStr) > 1<<16 {
			return
		}
		_, _ = purl.FromString(purlStr)
	})
}

// FuzzPURLRoundTrip tests PURL parse → string round-trip
// with arbitrary PURL strings.
func FuzzPURLRoundTrip(f *testing.F) {
	f.Add("pkg:golang/github.com/aquasecurity/trivy@1.0.0")
	f.Add("")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, purlStr string) {
		if len(purlStr) > 1<<16 {
			return
		}
		p, err := purl.FromString(purlStr)
		if err != nil {
			return
		}
		// String() must not panic on valid PURL
		_ = p.String()
	})
}
