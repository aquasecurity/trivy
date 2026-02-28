package module

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

// TestFreeCallSignature is a regression test for a bug where free() was called
// with only one argument (ptr) instead of two (ptr, size).
//
// The WASM SDK exports: free(ptr uint32, size uint32)
// wazero enforces strict parameter counts, so calling free with a wrong number
// of arguments returns an error. Previously this error was silently ignored
// (via errcheck nolint), causing a memory leak that eventually crashed the WASM
// module with errors like:
//   - "malloc error: module closed with exit_code(4)"
//   - "malloc error: wasm error: out of bounds memory access"
//   - "malloc error: runtime error: invalid memory address or nil pointer dereference"
func TestFreeCallSignature(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Test satisfied adequately by Linux tests")
	}

	ctx := t.Context()

	wasmCode, err := os.ReadFile("testdata/scanner/scanner.wasm")
	require.NoError(t, err, "scanner.wasm not found; run 'mage test:generateModules' first")

	cache := wazero.NewCompilationCache()
	defer cache.Close(ctx)

	mod, err := newWASMPlugin(ctx, cache, wasmCode)
	require.NoError(t, err)
	defer mod.Close(ctx)

	const allocSize = 64

	t.Run("free with correct args (ptr, size) succeeds", func(t *testing.T) {
		// Allocate a small buffer via malloc — this is exactly what marshal() and
		// stringToPtrSize() do before returning ptr+size to the caller.
		results, err := mod.malloc.Call(ctx, allocSize)
		require.NoError(t, err)
		require.Len(t, results, 1)
		ptr := results[0]
		_, err = mod.free.Call(ctx, ptr, allocSize)
		assert.NoError(t, err,
			"free(ptr, size) must succeed — the WASM SDK expects two parameters")
	})

	t.Run("free with wrong args (ptr only) fails", func(t *testing.T) {
		// Re-allocate since the previous buffer was freed
		results, err := mod.malloc.Call(ctx, allocSize)
		require.NoError(t, err)
		ptr := results[0]

		_, err = mod.free.Call(ctx, ptr) // only one arg — this is the old buggy call
		assert.ErrorContainsf(t, err,
			"expected 2 params, but passed 1",
			"free(ptr) with missing size argument must fail — "+
				"this was the root cause of the WASM memory leak")
	})
}
