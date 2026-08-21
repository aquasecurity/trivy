package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func TestTypeIndividualPkgs_Node(t *testing.T) {
	assert.Contains(t, analyzer.TypeIndividualPkgs, analyzer.TypeNode)
}
