package helm_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/set"
)

func addFiles(t *testing.T, dst fstest.MapFS, fsys fs.FS, prefix string) {
	t.Helper()
	require.NoError(t, fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		dst[prefix+"/"+path] = &fstest.MapFile{Data: data}
		return nil
	}))
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

func scanFS(t *testing.T, fsys fs.FS, opts ...options.ScannerOption) scan.Results {
	t.Helper()
	defaultOpts := []options.ScannerOption{
		rego.WithEmbeddedPolicies(true),
		rego.WithEmbeddedLibraries(true),
	}
	scanner := helm.New(append(defaultOpts, opts...)...)
	results, err := scanner.ScanFS(t.Context(), fsys, ".")
	require.NoError(t, err)
	return results
}

func TestScanner_ScanFS(t *testing.T) {
	tests := []struct {
		name   string
		target string
		opts   []options.ScannerOption
		assert func(t *testing.T, results scan.Results)
	}{
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
				assert.Equal(t, "templates/deployment.yaml", ignored[0].Metadata().Range().GetFilename())
			},
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
			name:   "non-helm chart does not error",
			target: filepath.Join("testdata", "non-helm-chart"),
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
			fsys := testutil.TxtarToFS(t, tt.target+".txtar")
			results := scanFS(t, fsys, tt.opts...)
			if tt.assert != nil {
				tt.assert(t, results)
			}
		})
	}
}

func TestScanner_ScanFS_Archive(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		opts     []options.ScannerOption
		expected []string
	}{
		{
			name: "archived chart",
			path: filepath.Join("testdata", "testchart.txtar"),
			// TODO: KSV-0018 should be ignored via # trivy:ignore:KSV018 in deployment.yaml,
			// but ignore annotations are not processed when scanning archives.
			expected: []string{
				"KSV-0001", "KSV-0003",
				"KSV-0011", "KSV-0012", "KSV-0014",
				"KSV-0015", "KSV-0016", "KSV-0018",
				"KSV-0020", "KSV-0021", "KSV-0030",
				"KSV-0104", "KSV-0106",
				"KSV-0117", "KSV-0110", "KSV-0118",
				"KSV-0004",
			},
		},
		{
			name: "with custom check",
			path: filepath.Join("testdata", "testchart.txtar"),
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
			// TODO: KSV-0018 should be ignored via # trivy:ignore:KSV018 in deployment.yaml,
			// but ignore annotations are not processed when scanning archives.
			expected: []string{
				"KSV-0001", "KSV-0003",
				"KSV-0011", "KSV-0012", "KSV-0014",
				"KSV-0015", "KSV-0016", "KSV-0018",
				"KSV-0020", "KSV-0021", "KSV-0030",
				"KSV-0104", "KSV-0106",
				"KSV-0117", "KSV-0110", "KSV-0118",
				"KSV-0004", "USR-ID001",
			},
		},
		{
			name: "scanner with missing chart name can recover",
			path: filepath.Join("testdata", "aws-cluster-autoscaler.txtar"),
			expected: []string{
				"KSV-0014", "KSV-0023", "KSV-0030",
				"KSV-0104", "KSV-0003", "KSV-0018",
				"KSV-0118", "KSV-0012", "KSV-0106",
				"KSV-0016", "KSV-0001", "KSV-0011",
				"KSV-0015", "KSV-0021", "KSV-0110", "KSV-0020",
				"KSV-0004",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := testutil.FSToTarGz(t, testutil.TxtarToFS(t, tt.path), "chart")
			fsys := fstest.MapFS{"chart.tar.gz": {Data: data}}

			opts := []options.ScannerOption{
				rego.WithEmbeddedPolicies(true),
				rego.WithEmbeddedLibraries(true),
			}
			scanner := helm.New(append(opts, tt.opts...)...)
			results, err := scanner.ScanFS(t.Context(), fsys, "chart.tar.gz")
			require.NoError(t, err)

			assertIds(tt.expected)(t, results)
		})
	}
}

func TestScanner_ScanFS_ChartDiscovery(t *testing.T) {
	runScan := func(t *testing.T, fsys fs.FS) scan.Results {
		t.Helper()
		results := scanFS(t, fsys)
		return results.GetFailed()
	}

	testchartFS := testutil.TxtarToFS(t, filepath.Join("testdata", "testchart.txtar"))
	autoscalerFS := testutil.TxtarToFS(t, filepath.Join("testdata", "aws-cluster-autoscaler.txtar"))

	t.Run("directory and archived charts both detected", func(t *testing.T) {
		testchartDir := fstest.MapFS{}
		addFiles(t, testchartDir, testchartFS, "testchart")
		autoscalerArchive := testutil.FSToTarGz(t, autoscalerFS, "aws-cluster-autoscaler")

		baselineTestchart := len(runScan(t, testchartDir))
		baselineAutoscaler := len(runScan(t, fstest.MapFS{
			"autoscaler.tgz": {Data: autoscalerArchive},
		}))

		combined := fstest.MapFS{"autoscaler.tgz": {Data: autoscalerArchive}}
		addFiles(t, combined, testchartFS, "testchart")

		assert.Equal(t, baselineTestchart+baselineAutoscaler, len(runScan(t, combined)))
	})

	t.Run("archive inside chart directory is skipped", func(t *testing.T) {
		baseline := fstest.MapFS{}
		addFiles(t, baseline, testchartFS, "testchart")
		baselineCount := len(runScan(t, baseline))

		archiveData := testutil.FSToTarGz(t, testchartFS, "testchart")
		combined := fstest.MapFS{"testchart/testchart.tgz": {Data: archiveData}}
		addFiles(t, combined, testchartFS, "testchart")

		assert.Equal(t, baselineCount, len(runScan(t, combined)))
	})

	t.Run("archive next to chart directory is skipped", func(t *testing.T) {
		baseline := fstest.MapFS{}
		addFiles(t, baseline, testchartFS, "testchart")
		baselineCount := len(runScan(t, baseline))

		archiveData := testutil.FSToTarGz(t, testchartFS, "testchart")
		combined := fstest.MapFS{"testchart.tgz": {Data: archiveData}}
		addFiles(t, combined, testchartFS, "testchart")

		assert.Equal(t, baselineCount, len(runScan(t, combined)))
	})
}
