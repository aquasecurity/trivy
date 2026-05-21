package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderedChartFiles(t *testing.T) {
	t.Run("chart nested in subdirectory", func(t *testing.T) {
		// Chart.yaml is at parent/my-chart/Chart.yaml, so rootPath has multiple path segments.
		// On Windows, filepath.Dir would return OS-specific separators, causing TrimPrefix
		// to fail and LoadFiles to not find Chart.yaml at the chart root.
		p, err := New(".")
		require.NoError(t, err)
		require.NoError(t, p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", "nested-chart")), "."))

		_, err = p.RenderedChartFiles()
		require.NoError(t, err)
	})
}

func TestParseFS(t *testing.T) {
	t.Run("source chart is located next to an same archived chart", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)
		require.NoError(t, p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", "chart-and-archived-chart")), "."))

		expectedFiles := []string{
			"my-chart/Chart.yaml",
			"my-chart/templates/pod.yaml",
		}
		assert.ElementsMatch(t, expectedFiles, lo.Keys(p.filepaths))
	})

	t.Run("archive with symlinks", func(t *testing.T) {
		// mkdir -p chart && cd $_
		// touch Chart.yaml
		// mkdir -p dir && cp -p Chart.yaml dir/Chart.yaml
		// mkdir -p sym-to-file && ln -s ../Chart.yaml sym-to-file/Chart.yaml
		// ln -s dir sym-to-dir
		// mkdir rec-sym && touch rec-sym/Chart.yaml
		// ln -s . ./rec-sym/a
		// cd .. && tar -czvf chart.tar.gz chart && rm -rf chart
		p, err := New(".")
		require.NoError(t, err)

		fsys := os.DirFS(filepath.Join("testdata", "archive-with-symlinks"))
		require.NoError(t, p.ParseFS(t.Context(), fsys, "chart.tar.gz"))

		expectedFiles := []string{
			"chart/Chart.yaml",
			"chart/dir/Chart.yaml",
			"chart/rec-sym/Chart.yaml",
			"chart/rec-sym/a/Chart.yaml",
			"chart/sym-to-dir/Chart.yaml",
			"chart/sym-to-file/Chart.yaml",
		}
		assert.ElementsMatch(t, expectedFiles, lo.Keys(p.filepaths))
	})

	t.Run("chart with multiple archived deps", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)

		fsys := os.DirFS(filepath.Join("testdata", "multiple-archived-deps"))
		require.NoError(t, p.ParseFS(t.Context(), fsys, "."))

		expectedFiles := []string{
			"Chart.yaml",
			"charts/common-2.26.0.tgz",
			"charts/opentelemetry-collector-0.108.0.tgz",
		}
		assert.ElementsMatch(t, expectedFiles, lo.Keys(p.filepaths))
	})

	t.Run("archives are not dependencies", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)

		fsys := os.DirFS(filepath.Join("testdata", "non-deps-archives"))
		require.NoError(t, p.ParseFS(t.Context(), fsys, "."))

		expectedFiles := []string{
			"Chart.yaml",
			"backup_charts/wordpress-operator/Chart.yaml",
			"backup_charts/mysql-operator/Chart.yaml",
		}
		assert.Subset(t, lo.Keys(p.filepaths), expectedFiles)
	})
}
