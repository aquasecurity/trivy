package test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_helm_parser(t *testing.T) {

	tests := []struct {
		testName  string
		chartName string
	}{
		{
			testName:  "Parsing directory 'testchart'",
			chartName: "testchart",
		},
		{
			testName:  "Parsing directory with tarred dependency",
			chartName: "with-tarred-dep",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			chartName := test.chartName

			t.Logf("Running test: %s", test.testName)

			helmParser := parser.New(chartName)
			err := helmParser.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", chartName)), ".")
			require.NoError(t, err)
			manifests, err := helmParser.RenderedChartFiles()
			require.NoError(t, err)

			assert.Len(t, manifests, 3)

			for _, manifest := range manifests {
				expectedPath := filepath.Join("testdata", "expected", chartName, manifest.TemplateFilePath)

				expectedContent, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				got := strings.ReplaceAll(manifest.ManifestContent, "\r\n", "\n")
				assert.Equal(t, strings.ReplaceAll(string(expectedContent), "\r\n", "\n"), got)
			}
		})
	}
}

func Test_helm_parser_where_name_non_string(t *testing.T) {

	tests := []struct {
		testName  string
		chartName string
	}{
		{
			testName:  "Scanning chart with integer for name",
			chartName: "numberName",
		},
	}

	for _, test := range tests {
		chartName := test.chartName

		t.Logf("Running test: %s", test.testName)

		helmParser := parser.New(chartName)
		err := helmParser.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", chartName)), ".")
		require.NoError(t, err)
	}
}

func Test_tar_is_chart(t *testing.T) {

	tests := []struct {
		testName    string
		archiveFile string
		isHelmChart bool
	}{
		{
			testName:    "standard tarball",
			archiveFile: "mysql-8.8.26.tar",
			isHelmChart: true,
		},
		{
			testName:    "gzip tarball with tar.gz extension",
			archiveFile: "mysql-8.8.26.tar.gz",
			isHelmChart: true,
		},
		{
			testName:    "broken gzip tarball with tar.gz extension",
			archiveFile: "aws-cluster-autoscaler-bad.tar.gz",
			isHelmChart: true,
		},
		{
			testName:    "gzip tarball with tgz extension",
			archiveFile: "mysql-8.8.26.tgz",
			isHelmChart: true,
		},
		{
			testName:    "gzip tarball that has nothing of interest in it",
			archiveFile: "nope.tgz",
			isHelmChart: false,
		},
	}

	for _, test := range tests {

		t.Logf("Running test: %s", test.testName)
		testPath := filepath.Join("testdata", test.archiveFile)
		file, err := os.Open(testPath)
		defer func() { _ = file.Close() }()
		require.NoError(t, err)

		assert.Equal(t, test.isHelmChart, detection.IsHelmChartArchive(test.archiveFile, file))

		_ = file.Close()
	}
}

func Test_helm_tarball_parser(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		archiveFile string
	}{
		{
			testName:    "standard tarball",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tar",
		},
		{
			testName:    "gzip tarball with tar.gz extension",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tar.gz",
		},
		{
			testName:    "gzip tarball with tgz extension",
			chartName:   "mysql",
			archiveFile: "mysql-8.8.26.tgz",
		},
	}

	for _, test := range tests {

		t.Logf("Running test: %s", test.testName)

		testPath := filepath.Join("testdata", test.archiveFile)

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveFile)
		require.NoError(t, copyArchive(testPath, testFileName))

		testFs := os.DirFS(testTemp)

		helmParser := parser.New(test.archiveFile)
		err := helmParser.ParseFS(context.TODO(), testFs, ".")
		require.NoError(t, err)

		manifests, err := helmParser.RenderedChartFiles()
		require.NoError(t, err)

		assert.Len(t, manifests, 6)

		oneOf := []string{
			"configmap.yaml",
			"statefulset.yaml",
			"svc-headless.yaml",
			"svc.yaml",
			"secrets.yaml",
			"serviceaccount.yaml",
		}

		for _, manifest := range manifests {
			filename := filepath.Base(manifest.TemplateFilePath)
			assert.Contains(t, oneOf, filename)

			if strings.HasSuffix(manifest.TemplateFilePath, "secrets.yaml") {
				continue
			}
			expectedPath := filepath.Join("testdata", "expected", test.chartName, manifest.TemplateFilePath)

			expectedContent, err := os.ReadFile(expectedPath)
			require.NoError(t, err)

			assert.Equal(t, strings.ReplaceAll(string(expectedContent), "\r\n", "\n"), strings.ReplaceAll(manifest.ManifestContent, "\r\n", "\n"))
		}
	}
}
