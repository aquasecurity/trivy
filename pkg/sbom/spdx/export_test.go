package spdx

import (
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/aquasecurity/trivy/pkg/digest"
)

// Bridge to expose spdx marshaler internals to tests in the spdx_test package.

// NormalizeLicenses exports normalizeLicenses for testing.
func (m *Marshaler) NormalizeLicenses(licenses []string) (string, []*spdx.OtherLicense) {
	return m.normalizeLicenses(licenses)
}

// SpdxChecksums exports spdxChecksums for testing.
func (m *Marshaler) SpdxChecksums(digests []digest.Digest) []common.Checksum {
	return m.spdxChecksums(digests)
}
