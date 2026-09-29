package spdx

import "github.com/spdx/tools-golang/spdx"

// Bridge to expose spdx marshaler internals to tests in the spdx_test package.

// NormalizeLicenses exports normalizeLicenses for testing.
func (m *Marshaler) NormalizeLicenses(licenses []string) (string, []*spdx.OtherLicense) {
	return m.normalizeLicenses(licenses)
}
