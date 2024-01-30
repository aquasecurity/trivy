package test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Kubernetes_RegoPoliciesFromDisk(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/kubernetes")
	require.NoError(t, err)

	scanner := kubernetes.NewScanner(
		options.ScannerWithPerResultTracing(true),
		options.ScannerWithEmbeddedPolicies(true),
		options.ScannerWithEmbeddedLibraries(true),
	)

	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/kubernetes")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() == "optional" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			var matched bool
			for _, result := range results {
				if result.Rule().HasID(entry.Name()) {

					failCase := fmt.Sprintf("test/testdata/kubernetes/%s/denied.yaml", entry.Name())
					passCase := fmt.Sprintf("test/testdata/kubernetes/%s/allowed.yaml", entry.Name())

					switch result.Range().GetFilename() {
					case failCase:
						assert.Equal(t, scan.StatusFailed, result.Status(), "Rule should have failed, but didn't.")
						assert.Greater(t, result.Range().GetStartLine(), 0, "We should have line numbers for a failure")
						assert.Greater(t, result.Range().GetEndLine(), 0, "We should have line numbers for a failure")
						matched = true
					case passCase:
						assert.Equal(t, scan.StatusPassed, result.Status(), "Rule should have passed, but didn't.")
						matched = true
					default:
						if strings.Contains(result.Range().GetFilename(), entry.Name()) {
							t.Fatal(result.Range().GetFilename())
						}
						continue
					}

					if t.Failed() {
						fmt.Println("Test failed - rego trace follows:")
						for _, trace := range result.Traces() {
							fmt.Println(trace)
						}
					}
				}
			}
			assert.True(t, matched, "Neither a pass or fail result was found for %s - did you add example code for it?", entry.Name())
		})
	}
}

func Test_Kubernetes_RegoPoliciesEmbedded(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/kubernetes")
	require.NoError(t, err)

	scanner := kubernetes.NewScanner(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true), options.ScannerWithEmbeddedLibraries(true))

	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/kubernetes")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() == "optional" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			var matched bool
			for _, result := range results {
				if result.Rule().HasID(entry.Name()) {

					failCase := fmt.Sprintf("test/testdata/kubernetes/%s/denied.yaml", entry.Name())
					passCase := fmt.Sprintf("test/testdata/kubernetes/%s/allowed.yaml", entry.Name())

					switch result.Range().GetFilename() {
					case failCase:
						assert.Equal(t, scan.StatusFailed, result.Status(), "Rule should have failed, but didn't.")
						assert.Greater(t, result.Range().GetStartLine(), 0, "We should have line numbers for a failure")
						assert.Greater(t, result.Range().GetEndLine(), 0, "We should have line numbers for a failure")
						matched = true
					case passCase:
						assert.Equal(t, scan.StatusPassed, result.Status(), "Rule should have passed, but didn't.")
						matched = true
					default:
						continue
					}

					if t.Failed() {
						fmt.Println("Test failed - rego trace follows:")
						for _, trace := range result.Traces() {
							fmt.Println(trace)
						}
					}
				}
			}
			assert.True(t, matched, "Neither a pass or fail result was found for %s - did you add example code for it?", entry.Name())
		})
	}
}
