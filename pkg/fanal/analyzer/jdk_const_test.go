package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func TestTypeJDKRegistration(t *testing.T) {
	assert.Contains(t, analyzer.TypeLanguages, analyzer.TypeJDK)
	assert.Contains(t, analyzer.TypeIndividualPkgs, analyzer.TypeJDK)
}
