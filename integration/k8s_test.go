//go:build k8s_integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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

		// it uses a fixed version of trivy-checks bundle - v1.11.2
		// its hash is sha256:f3ea8227f838a985f0c884909e9d226362f5fc5ab6021310a179fbb24c5b57fd
		osArgs := []string{
			"--cache-dir", cacheDir,
			"k8s",
			"kind-kind-test",
			"--report", "summary",
			"--checks-bundle-repository", "mirror.gcr.io/aquasec/trivy-checks:1.11.2@sha256:f3ea8227f838a985f0c884909e9d226362f5fc5ab6021310a179fbb24c5b57fd",
			"-q",
			"--timeout", "5m0s",
			"--format", "json",
			"--output", outputFile,
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

		// Collect IDs (CVEs for vulns, IDs for failed misconfigs), allowing duplicates.
		ids := k8sFindingIDs{}
		for _, r := range results {
			for _, v := range r.Vulnerabilities {
				if v.VulnerabilityID != "" {
					ids.Vulnerabilities = append(ids.Vulnerabilities, v.VulnerabilityID)
				}
			}
			for _, m := range r.Misconfigurations {
				if m.Status == types.MisconfStatusFailure && m.ID != "" {
					ids.Misconfigurations = append(ids.Misconfigurations, m.ID)
				}
			}
		}

		// Sort for deterministic golden files
		sort.Strings(ids.Vulnerabilities)
		sort.Strings(ids.Misconfigurations)

		fixture := filepath.Join("testdata", "fixtures", "k8s", "summary-ids.json.golden")
		if *update {
			// Update fixture with current IDs (duplicates kept, sorted)
			// Note: mage test:k8s may create additional k8s artifacts.
			f, err := os.Create(fixture)
			require.NoError(t, err)
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			require.NoError(t, enc.Encode(ids))
			t.Logf("updated fixture: %s", fixture)
			return
		}

		// Read expected IDs from fixture and compare
		ef, err := os.Open(fixture)
		require.NoError(t, err)
		defer ef.Close()

		var want k8sFindingIDs
		require.NoError(t, json.NewDecoder(ef).Decode(&want))
		assert.Equal(t, want, ids)
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

// k8sFindingIDs is the structure saved into the golden file.
type k8sFindingIDs struct {
	Vulnerabilities   []string `json:"vulnerabilities"`
	Misconfigurations []string `json:"misconfigurations"`
}
