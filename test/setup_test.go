package test

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/terraform"
	tfScanner "github.com/aquasecurity/trivy/pkg/scanners/terraform"
	"github.com/aquasecurity/trivy/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/require"
)

func createModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
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

func scanHCLWithWorkspace(t *testing.T, source string, workspace string) scan.Results {
	return scanHCL(t, source, tfScanner.ScannerWithWorkspaceName(workspace))
}

func scanHCL(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})

	localScanner := tfScanner.New(append(opts, options.ScannerWithEmbeddedPolicies(false))...)
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}

func scanJSON(t *testing.T, source string) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf.json": source,
	})

	s := tfScanner.New(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))
	results, _, err := s.ScanFSWithMetrics(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}
