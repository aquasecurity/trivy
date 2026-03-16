package scan

import (
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
)

// Bridge to expose scan internals to tests in the scan_test package.

// GenerateArtifactID exports generateArtifactID for testing.
func (s Service) GenerateArtifactID(artifactInfo artifact.Reference) string {
	return s.generateArtifactID(artifactInfo)
}
