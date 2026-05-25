package parser_test

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
)

func assertManifestEqual(t *testing.T, fsys fs.FS, path, actual string) {
	t.Helper()
	expected, err := fs.ReadFile(fsys, path)
	require.NoError(t, err)
	assert.Equal(t, normalizeManifest(string(expected)), normalizeManifest(actual))
}

func normalizeManifest(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimRight(s, "\n")
}

func TestParseFS(t *testing.T) {
	tests := []struct {
		name          string
		chartName     string
		opts          []parser.Option
		manifestCount int
		wantErr       string
		wantParseErr  string
	}{
		{
			name:          "simple chart",
			chartName:     "testchart",
			manifestCount: 3,
		},
		{
			name:          "chart with integer name",
			chartName:     "chart-with-integer-name",
			manifestCount: 0,
		},
		{
			name:         "chart without name returns error",
			chartName:    "chart-without-name",
			wantParseErr: "chart.metadata.name is required",
		},
		{
			name:          "values file option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "values.yaml"))},
			manifestCount: 3,
		},
		{
			name:         "non-existent values file",
			chartName:    "testchart",
			opts:         []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "nonexistent.yaml"))},
			wantParseErr: "nonexistent.yaml",
		},
		{
			name:          "set value option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValues("securityContext.runAsUser=0")},
			manifestCount: 3,
		},
		{
			name:          "set string value option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithStringValues("securityContext.runAsUser=0")},
			manifestCount: 3,
		},
		{
			name:          "set file value option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithFileValues("image.tag=" + path.Join("testdata", "values.yaml"))},
			manifestCount: 3,
		},
		{
			name:          "api versions option",
			chartName:     "with-api-version",
			opts:          []parser.Option{parser.OptionWithAPIVersions("policy/v1/PodDisruptionBudget")},
			manifestCount: 1,
		},
		{
			name:          "kube version option",
			chartName:     "with-kube-version",
			opts:          []parser.Option{parser.OptionWithKubeVersion("1.60")},
			manifestCount: 1,
		},
		{
			name:      "invalid kube version",
			chartName: "with-kube-version",
			opts:      []parser.Option{parser.OptionWithKubeVersion("a.b.c")},
			wantErr:   `could not parse "a.b.c" as version`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New(tt.opts...)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			fsys := testutil.TxtarToFS(t, filepath.Join("testdata", tt.chartName+".txtar"))
			manifests, err := p.ParseFS(t.Context(), fsys, ".")
			if tt.wantParseErr != "" {
				assert.ErrorContains(t, err, tt.wantParseErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, manifests, tt.manifestCount)
		})
	}
}

func TestParseFS_Rendered(t *testing.T) {
	tests := []struct {
		name         string
		chartName    string
		opts         []parser.Option
		expectedFile string
	}{
		{
			name:         "simple chart",
			chartName:    "testchart",
			expectedFile: "testchart.txtar",
		},
		{
			name:         "values file option",
			chartName:    "testchart",
			opts:         []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "values.yaml"))},
			expectedFile: "testchart-with-options.txtar",
		},
		{
			name:         "set value option",
			chartName:    "testchart",
			opts:         []parser.Option{parser.OptionWithValues("securityContext.runAsUser=0")},
			expectedFile: "testchart-with-options.txtar",
		},
		{
			name:         "api versions option",
			chartName:    "with-api-version",
			opts:         []parser.Option{parser.OptionWithAPIVersions("policy/v1/PodDisruptionBudget")},
			expectedFile: "with-api-version.txtar",
		},
		{
			name:         "kube version option",
			chartName:    "with-kube-version",
			opts:         []parser.Option{parser.OptionWithKubeVersion("1.60")},
			expectedFile: "with-kube-version.txtar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New(tt.opts...)
			require.NoError(t, err)

			fsys := testutil.TxtarToFS(t, filepath.Join("testdata", tt.chartName+".txtar"))
			manifests, err := p.ParseFS(t.Context(), fsys, ".")
			require.NoError(t, err)

			expectedFS := testutil.TxtarToFS(t, filepath.Join("testdata", "expected", tt.expectedFile))
			for _, manifest := range manifests {
				assertManifestEqual(t, expectedFS, manifest.Path, manifest.Content)
			}
		})
	}
}

func TestParseFS_WithArchivedDependency(t *testing.T) {
	expectedFS := testutil.TxtarToFS(t, filepath.Join("testdata", "expected", "chart-with-packaged-dep.txtar"))

	p, err := parser.New()
	require.NoError(t, err)

	// os.DirFS is used here because the chart contains a binary .tgz dependency (common-1.16.1.tgz)
	// which cannot be embedded in a txtar file.
	manifests, err := p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", "chart-with-packaged-dep")), ".")
	require.NoError(t, err)
	assert.Len(t, manifests, 3)

	for _, manifest := range manifests {
		assertManifestEqual(t, expectedFS, manifest.Path, manifest.Content)
	}
}

func TestParseArchive(t *testing.T) {
	expectedFS := testutil.TxtarToFS(t, filepath.Join("testdata", "expected", "testchart.txtar"))
	fsys := testutil.TxtarToFS(t, filepath.Join("testdata", "testchart.txtar"))
	archiveData := testutil.FSToTarGz(t, fsys, "testchart")
	archiveFS := fstest.MapFS{"testchart.tar.gz": {Data: archiveData}}

	p, err := parser.New()
	require.NoError(t, err)

	manifests, err := p.ParseArchive(t.Context(), archiveFS, "testchart.tar.gz")
	require.NoError(t, err)
	assert.Len(t, manifests, 3)

	for _, manifest := range manifests {
		assertManifestEqual(t, expectedFS, manifest.Path, manifest.Content)
	}
}

func TestParseArchive_ChartWithoutName(t *testing.T) {
	fsys := testutil.TxtarToFS(t, filepath.Join("testdata", "chart-without-name.txtar"))
	archiveFS := fstest.MapFS{"chart-without-name.tgz": {Data: testutil.FSToTarGz(t, fsys, "chart-without-name")}}

	p, err := parser.New()
	require.NoError(t, err)

	_, err = p.ParseArchive(t.Context(), archiveFS, "chart-without-name.tgz")
	assert.ErrorContains(t, err, "chart.metadata.name is required")
}

func TestParseArchive_InvalidArchive(t *testing.T) {
	p, err := parser.New()
	require.NoError(t, err)

	fsys := fstest.MapFS{"chart.tgz": {Data: []byte("not a valid archive")}}
	_, err = p.ParseArchive(t.Context(), fsys, "chart.tgz")
	assert.ErrorContains(t, err, "load archive files")
}

// TODO: move to pkg/iac/detection
func TestIsHelmChartArchive(t *testing.T) {
	chartYAML := "apiVersion: v2\nname: test\nversion: 1.0.0\n"
	helmFS := fstest.MapFS{"chart/Chart.yaml": {Data: []byte(chartYAML)}}
	nonHelmFS := fstest.MapFS{"chart/README.md": {Data: []byte("# readme\n")}}

	tests := []struct {
		name     string
		filename string
		fsys     fs.FS
		expected bool
	}{
		{
			name:     "gzip tarball with tar.gz extension",
			filename: "chart.tar.gz",
			fsys:     helmFS,
			expected: true,
		},
		{
			name:     "gzip tarball with tgz extension",
			filename: "chart.tgz",
			fsys:     helmFS,
			expected: true,
		},
		{
			name:     "non-helm tgz",
			filename: "chart.tgz",
			fsys:     nonHelmFS,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := testutil.FSToTarGz(t, tt.fsys, "chart")
			isArchive := detection.IsHelmChartArchive(tt.filename, bytes.NewReader(data))
			assert.Equal(t, tt.expected, isArchive)
		})
	}
}
