package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFS(t *testing.T) {
	t.Run("source chart is located next to an same archived chart", func(t *testing.T) {
		p, err := New(".")
		require.NoError(t, err)
		require.NoError(t, p.ParseFS(t.Context(), os.DirFS(filepath.Join("testdata", "chart-and-archived-chart")), "."))

		expectedFiles := []string{
			"my-chart/Chart.yaml",
			"my-chart/templates/pod.yaml",
			"my-chart-0.1.0.tgz",
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
			"backup_charts/wordpress-operator-0.12.4.tgz",
			"backup_charts/mysql-operator-2.2.2.tgz",
		}
		assert.Subset(t, lo.Keys(p.filepaths), expectedFiles)
	})
}
