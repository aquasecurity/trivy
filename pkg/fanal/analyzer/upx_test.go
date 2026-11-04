package analyzer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils/upx"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

func TestAnalyzerGroup_AnalyzeFile_UPX(t *testing.T) {
	if !upx.HasUPX() {
		t.Skip("upx binary not found in PATH")
	}

	tempDir := t.TempDir()
	goSource := filepath.Join(tempDir, "main.go")
	err := os.WriteFile(goSource, []byte(`package main
import "fmt"
func main() {
	fmt.Println("hello upx")
}
`), 0600)
	require.NoError(t, err)

	origBin := filepath.Join(tempDir, "bin")
	cmd := exec.Command("go", "build", "-o", origBin, goSource)
	require.NoError(t, cmd.Run())

	packedBin := filepath.Join(tempDir, "packed_bin")
	data, err := os.ReadFile(origBin)
	require.NoError(t, err)
	err = os.WriteFile(packedBin, data, 0755)
	require.NoError(t, err)

	cmdUpx := exec.Command("upx", packedBin)
	require.NoError(t, cmdUpx.Run())

	ag, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	// When DecompressUPX is false
	t.Run("DecompressUPX false", func(t *testing.T) {
		res := analyzer.NewAnalysisResult()
		limit := semaphore.NewWeighted(1)
		eg, egCtx := errgroup.WithContext(t.Context())

		fi, err := os.Stat(packedBin)
		require.NoError(t, err)

		opener := func() (xio.ReadSeekCloserAt, error) {
			return os.Open(packedBin)
		}

		err = ag.AnalyzeFile(egCtx, eg, limit, res, "", packedBin, fi, opener, nil, analyzer.AnalysisOptions{
			DecompressUPX: false,
		})
		require.NoError(t, err)
		require.NoError(t, eg.Wait())

		assert.Empty(t, res.Applications)
		assert.Empty(t, res.CustomResources)
	})

	// When DecompressUPX is true
	t.Run("DecompressUPX true", func(t *testing.T) {
		res := analyzer.NewAnalysisResult()
		limit := semaphore.NewWeighted(1)
		eg, egCtx := errgroup.WithContext(t.Context())

		fi, err := os.Stat(packedBin)
		require.NoError(t, err)

		opener := func() (xio.ReadSeekCloserAt, error) {
			return os.Open(packedBin)
		}

		err = ag.AnalyzeFile(egCtx, eg, limit, res, "", packedBin, fi, opener, nil, analyzer.AnalysisOptions{
			DecompressUPX: true,
		})
		require.NoError(t, err)
		require.NoError(t, eg.Wait())

		assert.NotEmpty(t, res.Applications)
		assert.Equal(t, types.GoBinary, res.Applications[0].Type)
		assert.Len(t, res.CustomResources, 1)
		assert.Equal(t, upx.CustomResourceType, res.CustomResources[0].Type)
		assert.Equal(t, packedBin, res.CustomResources[0].FilePath)
	})
}
