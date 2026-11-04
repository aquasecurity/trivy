package upx

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func TestDecompress(t *testing.T) {
	if !HasUPX() {
		t.Skip("upx binary not found in PATH")
	}

	tempDir := t.TempDir()
	goSource := filepath.Join(tempDir, "main.go")
	err := os.WriteFile(goSource, []byte(`package main
import "fmt"
func main() {
	fmt.Println("test")
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

	// Test non-UPX data
	t.Run("non UPX binary", func(t *testing.T) {
		r := bytes.NewReader([]byte("not a binary"))
		rAt, err := xio.NewReadSeekerAt(r)
		require.NoError(t, err)
		decompressed, cleanup, err := Decompress(context.Background(), rAt, int64(r.Len()))
		require.NoError(t, err)
		assert.Nil(t, decompressed)
		assert.Nil(t, cleanup)
	})

	// Test UPX binary
	t.Run("valid UPX binary", func(t *testing.T) {
		packedData, err := os.ReadFile(packedBin)
		require.NoError(t, err)

		r := bytes.NewReader(packedData)
		rAt, err := xio.NewReadSeekerAt(r)
		require.NoError(t, err)
		decompressed, cleanup, err := Decompress(context.Background(), rAt, int64(len(packedData)))
		require.NoError(t, err)
		require.NotNil(t, decompressed)
		defer cleanup()

		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(decompressed)
		require.NoError(t, err)
		assert.Equal(t, len(data), buf.Len())
	})
}
