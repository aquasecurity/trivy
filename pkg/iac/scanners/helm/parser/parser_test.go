package parser

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFS(t *testing.T) {
	t.Run("source chart is located next to an same archived chart", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)
		require.NoError(t, p.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", "chart-and-archived-chart")), "."))

		expectedFiles := []string{
			"my-chart/Chart.yaml",
			"my-chart/templates/pod.yaml",
		}
		assert.Equal(t, expectedFiles, p.filepaths)
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
		require.NoError(t, p.ParseFS(context.TODO(), fsys, "chart.tar.gz"))

		expectedFiles := []string{
			"chart/Chart.yaml",
			"chart/dir/Chart.yaml",
			"chart/rec-sym/Chart.yaml",
			"chart/rec-sym/a/Chart.yaml",
			"chart/sym-to-dir/Chart.yaml",
			"chart/sym-to-file/Chart.yaml",
		}
		assert.Equal(t, expectedFiles, p.filepaths)
	})

	t.Run("chart with multiple archived deps", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)

		fsys := os.DirFS(filepath.Join("testdata", "multiple-archived-deps"))
		require.NoError(t, p.ParseFS(context.TODO(), fsys, "."))

		expectedFiles := []string{
			"Chart.yaml",
			"charts/common-2.26.0.tgz",
			"charts/opentelemetry-collector-0.108.0.tgz",
		}
		assert.Equal(t, expectedFiles, p.filepaths)
	})

	t.Run("archives are not dependencies", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)

		fsys := os.DirFS(filepath.Join("testdata", "non-deps-archives"))
		require.NoError(t, p.ParseFS(context.TODO(), fsys, "."))

		expectedFiles := []string{
			"Chart.yaml",
			"backup_charts/wordpress-operator/Chart.yaml",
			"backup_charts/mysql-operator/Chart.yaml",
		}
		assert.Subset(t, p.filepaths, expectedFiles)
	})
}
