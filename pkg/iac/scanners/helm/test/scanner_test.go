package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/set"
)

func TestScanner_ScanFS(t *testing.T) {
	tests := []struct {
		name   string
		target string
		opts   []options.ScannerOption
		assert func(t *testing.T, results scan.Results)
	}{
		{
			name:   "archived chart",
			target: filepath.Join("testdata", "mysql-8.8.26.tar"),
			assert: assertIds([]string{
				"KSV-0001", "KSV-0003",
				"KSV-0011", "KSV-0012", "KSV-0014",
				"KSV-0015", "KSV-0016", "KSV-0018",
				"KSV-0020", "KSV-0021", "KSV-0030",
				"KSV-0104", "KSV-0106", "KSV-0125",
				"KSV-0004",
			}),
		},
		{
			name:   "chart in directory",
			target: filepath.Join("testdata", "testchart"),
			assert: func(t *testing.T, results scan.Results) {
				assertIds([]string{
					"KSV-0001", "KSV-0003",
					"KSV-0011", "KSV-0012", "KSV-0014",
					"KSV-0015", "KSV-0016",
					"KSV-0020", "KSV-0021", "KSV-0030",
					"KSV-0104", "KSV-0106",
					"KSV-0117", "KSV-0110", "KSV-0118",
					"KSV-0004",
				})(t, results)

				ignored := results.GetIgnored()
				assert.Len(t, ignored, 1)

				assert.Equal(t, "KSV-0018", ignored[0].Rule().ID)
				assert.Equal(t, "testchart/templates/deployment.yaml", ignored[0].Metadata().Range().GetFilename())
			},
		},
		{
			// TODO: The chart name isn't actually empty
			name:   "scanner with missing chart name can recover",
			target: filepath.Join("testdata", "aws-cluster-autoscaler-bad.tar.gz"),
			assert: assertIds([]string{
				"KSV-0014", "KSV-0023", "KSV-0030",
				"KSV-0104", "KSV-0003", "KSV-0018",
				"KSV-0118", "KSV-0012", "KSV-0106",
				"KSV-0016", "KSV-0001", "KSV-0011",
				"KSV-0015", "KSV-0021", "KSV-0110", "KSV-0020",
				"KSV-0004",
			}),
		},
		{
			name:   "with custom check",
			target: filepath.Join("testdata", "mysql-8.8.26.tar"),
			opts: []options.ScannerOption{
				rego.WithPolicyNamespaces("user"),
				rego.WithPolicyReader(strings.NewReader(`package user.kubernetes.ID001
__rego_metadata__ := {
	"id": "USR-ID001",
    "title": "Services not allowed",
    "severity": "LOW",
    "description": "Services are not allowed because of some reasons.",
}

__rego_input__ := {
    "selector": [
        {"type": "kubernetes"},
    ],
}

deny[res] {
    input.kind == "Service"
    msg := sprintf("Found service '%s' but services are not allowed", [input.metadata.name])
    res := result.new(msg, input)
}`)),
			},
			assert: assertIds([]string{
				"KSV-0001", "KSV-0003",
				"KSV-0011", "KSV-0012", "KSV-0014",
				"KSV-0015", "KSV-0016", "KSV-0018",
				"KSV-0020", "KSV-0021", "KSV-0030",
				"KSV-0104", "KSV-0106", "USR-ID001",
				"KSV-0004", "KSV-0125",
			}),
		},
		{
			name:   "template-based name",
			target: filepath.Join("testdata", "templated-name"),
			opts: []options.ScannerOption{
				rego.WithEmbeddedLibraries(false),
				rego.WithEmbeddedPolicies(false),
			},
		},
		{
			name:   "failed result contains the code",
			target: filepath.Join("testdata", "simmilar-templates"),
			opts: []options.ScannerOption{
				rego.WithEmbeddedPolicies(false),
				rego.WithEmbeddedLibraries(true),
				rego.WithPolicyNamespaces("user"),
				rego.WithPolicyReader(strings.NewReader(`# METADATA
# title: "Test rego"
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: USR-ID001
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID001

deny[res] {
    input.spec.replicas == 3
    res := result.new("Replicas are not allowed", input)
}`)),
			},
			assert: func(t *testing.T, results scan.Results) {
				failedResults := results.GetFailed()
				require.Len(t, failedResults, 1)
				code, err := failedResults[0].GetCode()
				require.NoError(t, err)
				assert.NotNil(t, code)
			},
		},
		{
			name:   "scan the subchart once",
			target: filepath.Join("testdata", "with-subchart"),
			opts: []options.ScannerOption{
				rego.WithEmbeddedPolicies(false),
				rego.WithEmbeddedLibraries(true),
				rego.WithPolicyNamespaces("user"),
				rego.WithPolicyReader(strings.NewReader(`# METADATA
# title: "Test rego"
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: USR-ID001
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
package user.kubernetes.ID001

import data.lib.kubernetes

deny[res] {
	container := kubernetes.containers[_]
	container.securityContext.readOnlyRootFilesystem == false
	res := result.new("set 'securityContext.readOnlyRootFilesystem' to true", container)
}`)),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []options.ScannerOption{
				rego.WithEmbeddedPolicies(true),
				rego.WithEmbeddedLibraries(true),
			}
			opts = append(opts, tt.opts...)
			scanner := helm.New(opts...)
			fsys := os.DirFS(filepath.Dir(tt.target))
			results, err := scanner.ScanFS(t.Context(), fsys, filepath.Base(tt.target))
			require.NoError(t, err)

			if tt.assert != nil {
				tt.assert(t, results)
			}
		})
	}
}

func assertIds(expected []string) func(t *testing.T, results scan.Results) {
	return func(t *testing.T, results scan.Results) {
		t.Helper()

		errorCodes := set.New[string]()
		for _, result := range results.GetFailed() {
			errorCodes.Append(result.Rule().ID)
		}
		assert.ElementsMatch(t, expected, errorCodes.Items())
	}
}

func TestScaningNonHelmChartDoesNotCauseError(t *testing.T) {
	fsys := fstest.MapFS{
		"testChart.yaml": &fstest.MapFile{Data: []byte(`foo: bar`)},
	}
	_, err := helm.New().ScanFS(t.Context(), fsys, ".")
	require.NoError(t, err)
}
