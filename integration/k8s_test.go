//go:build k8s_integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: the test required k8s (kind) cluster installed.
// "mage test:k8s" will run this test.

func TestK8s(t *testing.T) {
	// Set up testing DB
	cacheDir := initDB(t)
	t.Run("misconfig and vulnerability scan", func(t *testing.T) {
		// Set up the output file
		outputFile := filepath.Join(t.TempDir(), "output.json")

		osArgs := []string{
			"--cache-dir",
			cacheDir,
			"k8s",
			"kind-kind-test",
			"--report",
			"summary",
			"-q",
			"--timeout",
			"5m0s",
			"--format",
			"json",
			"--output",
			outputFile,
		}

		// Run Trivy
		err := execute(osArgs)
		require.NoError(t, err)

		var got report.ConsolidatedReport
		f, err := os.Open(outputFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&got)
		require.NoError(t, err)

		// Flatten findings
		results := lo.FlatMap(got.Findings, func(resource report.Resource, _ int) []types.Result {
			return resource.Results
		})

		// Aggregate severity counts and compare with fixture
		gotCounts := newK8sSeverityCounts()
		for _, r := range results {
			for _, v := range r.Vulnerabilities {
				gotCounts.Vulnerabilities[v.Severity]++
			}
			for _, m := range r.Misconfigurations {
				if m.Status == types.MisconfStatusFailure {
					gotCounts.Misconfigurations[m.Severity]++
				}
			}
		}

		fixture := filepath.Join("testdata", "fixtures", "k8s", "summary-severity.json.golden")
		if *update {
			// Update fixture with current counts
			f, err := os.Create(fixture)
			require.NoError(t, err)
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			require.NoError(t, enc.Encode(gotCounts))
			t.Logf("updated fixture: %s", fixture)
			return
		}

		// Read expected counts from fixture and compare
		ef, err := os.Open(fixture)
		require.NoError(t, err)
		defer ef.Close()

		var wantCounts k8sSeverityCounts
		require.NoError(t, json.NewDecoder(ef).Decode(&wantCounts))
		assert.Equal(t, wantCounts, gotCounts)
	})
	t.Run("kbom cycloneDx", func(t *testing.T) {
		// Set up the output file
		outputFile := filepath.Join(t.TempDir(), "output.json")
		osArgs := []string{
			"k8s",
			"kind-kind-test",
			"--format",
			"cyclonedx",
			"-q",
			"--output",
			outputFile,
		}

		// Run Trivy
		err := execute(osArgs)
		require.NoError(t, err)

		var got *cdx.BOM
		f, err := os.Open(outputFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&got)
		require.NoError(t, err)

		assert.Equal(t, got.Metadata.Component.Name, "k8s.io/kubernetes")
		assert.Equal(t, got.Metadata.Component.Type, cdx.ComponentType("platform"))

		// Has components
		assert.True(t, len(*got.Components) > 0)

		// Has dependecies
		assert.True(t, lo.SomeBy(*got.Dependencies, func(r cdx.Dependency) bool {
			return len(*r.Dependencies) > 0
		}))
	})
	t.Run("limited user test", func(t *testing.T) {
		// Set up the output file
		outputFile := filepath.Join(t.TempDir(), "output.json")

		osArgs := []string{
			"--cache-dir",
			cacheDir,
			"k8s",
			"limitedcontext",
			"--kubeconfig", "limitedconfig",
			"--report",
			"summary",
			"-q",
			"--timeout",
			"5m0s",
			"--include-namespaces", "limitedns",
			"--format",
			"json",
			"--output",
			outputFile,
		}

		// Run Trivy
		err := execute(osArgs)
		require.NoError(t, err)

		var got report.ConsolidatedReport
		f, err := os.Open(outputFile)
		require.NoError(t, err)
		defer f.Close()

		err = json.NewDecoder(f).Decode(&got)
		require.NoError(t, err)

		// Flatten findings
		results := lo.FlatMap(got.Findings, func(resource report.Resource, _ int) []types.Result {
			return resource.Results
		})

		// Has vulnerabilities
		assert.True(t, lo.SomeBy(results, func(r types.Result) bool {
			return len(r.Vulnerabilities) > 0
		}))

		// Has misconfigurations
		assert.True(t, lo.SomeBy(results, func(r types.Result) bool {
			return len(r.Misconfigurations) > 0
		}))

	})
}

// k8sSeverityCounts represents expected severity counts for the consolidated report.
type k8sSeverityCounts struct {
	Vulnerabilities   map[string]int `json:"vulnerabilities"`
	Misconfigurations map[string]int `json:"misconfigurations"`
}

func newK8sSeverityCounts() k8sSeverityCounts {
	// Initialize with all known severities to stabilize fixture order/diff
	return k8sSeverityCounts{
		Vulnerabilities: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"UNKNOWN":  0,
		},
		Misconfigurations: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"UNKNOWN":  0,
		},
	}
}
