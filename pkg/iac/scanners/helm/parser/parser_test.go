package parser_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
)

func assertManifestEqual(t *testing.T, expectedPath, actual string) {
	t.Helper()
	expectedContent, err := os.ReadFile(expectedPath)
	require.NoError(t, err)
	assert.Equal(t, normalizeManifest(string(expectedContent)), normalizeManifest(actual))
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
		expectedDir   string
		expectedError string
	}{
		{
			name:          "simple chart",
			chartName:     "testchart",
			manifestCount: 3,
			expectedDir:   filepath.Join("testdata", "expected", "testchart"),
		},
		{
			name:          "chart with tarred dependency",
			chartName:     "with-tarred-dep",
			manifestCount: 3,
			expectedDir:   filepath.Join("testdata", "expected", "with-tarred-dep"),
		},
		{
			name:          "chart with integer name",
			chartName:     "numberName",
			manifestCount: 0,
		},
		{
			name:          "values file option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValuesFile(filepath.Join("testdata", "values", "values.yaml"))},
			manifestCount: 3,
			expectedDir:   filepath.Join("testdata", "expected", "options", "testchart"),
		},
		{
			name:          "set value option",
			chartName:     "testchart",
			opts:          []parser.Option{parser.OptionWithValues("securityContext.runAsUser=0")},
			manifestCount: 3,
			expectedDir:   filepath.Join("testdata", "expected", "options", "testchart"),
		},
		{
			name:          "api versions option",
			chartName:     "with-api-version",
			opts:          []parser.Option{parser.OptionWithAPIVersions("policy/v1/PodDisruptionBudget")},
			manifestCount: 1,
			expectedDir:   filepath.Join("testdata", "expected", "options", "with-api-version"),
		},
		{
			name:          "kube version option",
			chartName:     "with-kube-version",
			opts:          []parser.Option{parser.OptionWithKubeVersion("1.60")},
			manifestCount: 1,
			expectedDir:   filepath.Join("testdata", "expected", "options", "with-kube-version"),
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

			manifests, err := p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", tt.chartName)), ".")
			require.NoError(t, err)
			assert.Len(t, manifests, tt.manifestCount)

			if tt.expectedDir != "" {
				for _, manifest := range manifests {
					assertManifestEqual(t, filepath.Join(tt.expectedDir, manifest.Path), manifest.Content)
				}
			}
		})
	}
}

func TestParseArchive(t *testing.T) {
	tests := []struct {
		name          string
		archiveFile   string
		manifestCount int
		expectedDir   string
	}{
		{
			name:          "tar.gz archive",
			archiveFile:   "mysql-8.8.26.tar.gz",
			manifestCount: 6,
			expectedDir:   filepath.Join("testdata", "expected", "mysql"),
		},
		{
			name:          "tgz archive",
			archiveFile:   "mysql-8.8.26.tgz",
			manifestCount: 6,
			expectedDir:   filepath.Join("testdata", "expected", "mysql"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New()
			require.NoError(t, err)

			manifests, err := p.ParseArchive(t.Context(), os.DirFS("testdata"), tt.archiveFile)
			require.NoError(t, err)
			assert.Len(t, manifests, tt.manifestCount)

			oneOf := []string{
				"configmap.yaml",
				"statefulset.yaml",
				"svc-headless.yaml",
				"svc.yaml",
				"secrets.yaml",
				"serviceaccount.yaml",
			}
			for _, manifest := range manifests {
				filename := filepath.Base(manifest.Path)
				assert.Contains(t, oneOf, filename)

				if strings.HasSuffix(manifest.Path, "secrets.yaml") {
					continue
				}
				assertManifestEqual(t, filepath.Join(tt.expectedDir, manifest.Path), manifest.Content)
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
