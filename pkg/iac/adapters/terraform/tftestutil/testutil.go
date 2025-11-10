package tftestutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func CreateModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(map[string]string{
		"source" + ext: source,
	})
	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	require.NoError(t, p.ParseFS(t.Context(), "."))
	modules, err := p.EvaluateAll(t.Context())
	require.NoError(t, err)
	return modules
}
