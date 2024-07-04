package terraform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func createModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func scanHCLWithWorkspace(t *testing.T, source, workspace string) scan.Results {
	return scanHCL(t, source, ScannerWithWorkspaceName(workspace))
}

func scanHCL(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})

	localScanner := New(append(opts, options.ScannerWithEmbeddedPolicies(false))...)
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}

func scanJSON(t *testing.T, source string) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf.json": source,
	})

	s := New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))
	results, err := s.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}
