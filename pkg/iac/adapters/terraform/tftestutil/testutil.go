package tftestutil

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func CreateModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})
	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(t.Context(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(t.Context())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}
