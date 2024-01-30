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
		p := New(".")
		require.NoError(t, p.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", "chart-and-archived-chart")), "."))

		expectedFiles := []string{
			"my-chart/Chart.yaml",
			"my-chart/templates/pod.yaml",
		}
		assert.Equal(t, expectedFiles, p.filepaths)
	})
}
