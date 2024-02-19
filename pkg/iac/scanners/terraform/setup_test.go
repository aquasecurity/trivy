package terraform

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/stretchr/testify/require"
)

func createModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func scanHCLWithWorkspace(t *testing.T, source string, workspace string) scan.Results {
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
	results, _, err := s.ScanFSWithMetrics(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}
