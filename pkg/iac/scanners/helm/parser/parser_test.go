package parser_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		expectedError string
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
			name:          "values file option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "values", "values.yaml"))},
			manifestCount: 3,
		},
		{
			name:          "set value option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValues("securityContext.runAsUser=0")},
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
			name:          "invalid kube version",
			chartName:     "with-kube-version",
			opts:          []parser.Option{parser.OptionWithKubeVersion("a.b.c")},
			expectedError: `could not parse "a.b.c" as version`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New(tt.opts...)
			if tt.expectedError != "" {
				require.EqualError(t, err, tt.expectedError)
				return
			}
			require.NoError(t, err)

			fsys := testutil.TxtarToFS(t, filepath.Join("testdata", tt.chartName+".txtar"))
			manifests, err := p.ParseFS(t.Context(), fsys, ".")
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
			opts:         []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "values", "values.yaml"))},
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

	manifests, err := p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", "chart-with-packaged-dep")), ".")
	require.NoError(t, err)
	assert.Len(t, manifests, 3)

	for _, manifest := range manifests {
		assertManifestEqual(t, expectedFS, manifest.Path, manifest.Content)
	}
}

func TestParseArchive(t *testing.T) {
	expectedFS := testutil.TxtarToFS(t, filepath.Join("testdata", "expected", "mysql.txtar"))

	tests := []struct {
		name        string
		archiveFile string
	}{
		{
			name:        "tar.gz archive",
			archiveFile: "mysql-8.8.26.tar.gz",
		},
		{
			name:        "tgz archive",
			archiveFile: "mysql-8.8.26.tgz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New()
			require.NoError(t, err)

			manifests, err := p.ParseArchive(t.Context(), os.DirFS("testdata"), tt.archiveFile)
			require.NoError(t, err)
			assert.Len(t, manifests, 6)

			for _, manifest := range manifests {
				if strings.HasSuffix(manifest.Path, "secrets.yaml") {
					continue
				}
				assertManifestEqual(t, expectedFS, manifest.Path, manifest.Content)
			}
		})
	}
}

func TestIsHelmChartArchive(t *testing.T) {
	tests := []struct {
		name        string
		archiveFile string
		isHelmChart bool
	}{
		{
			name:        "standard tarball",
			archiveFile: "mysql-8.8.26.tar",
			isHelmChart: true,
		},
		{
			name:        "gzip tarball with tar.gz extension",
			archiveFile: "mysql-8.8.26.tar.gz",
			isHelmChart: true,
		},
		{
			name:        "broken gzip tarball",
			archiveFile: "aws-cluster-autoscaler-bad.tar.gz",
			isHelmChart: true,
		},
		{
			name:        "gzip tarball with tgz extension",
			archiveFile: "mysql-8.8.26.tgz",
			isHelmChart: true,
		},
		{
			name:        "non-helm tgz",
			archiveFile: "nope.tgz",
			isHelmChart: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tt.archiveFile))
			require.NoError(t, err)
			defer f.Close()

			assert.Equal(t, tt.isHelmChart, detection.IsHelmChartArchive(tt.archiveFile, f))
		})
	}
}
