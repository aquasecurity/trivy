package resolvers

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	// Replace the non-thread-safe DeferredHandler with a real handler so that
	// concurrent download() calls don't trigger an unrelated logger data race.
	log.InitLogger(true, true)
}

// TestRemoteDownloadDoesNotMutateGlobalGetters verifies that download() does not
// write to the package-global getter.Getters map. Concurrent download() calls
// must only read the shared map (safe) and never write it.
//
// Run with -race to also catch concurrent map writes:
//
//	go test -race -run TestRemoteDownloadDoesNotMutateGlobalGetters ./pkg/iac/scanners/terraform/parser/resolvers/...
func TestRemoteDownloadDoesNotMutateGlobalGetters(t *testing.T) {
	// Snapshot the original global "file" getter.
	// go-getter initialises it to &FileGetter{} (Copy: false) at package init.
	original := getter.Getters["file"]
	require.NotNil(t, original, "precondition: global file getter should exist")

	srcDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "module.tf"), []byte("# test"), 0o600))

	// Run downloads concurrently — under -race this catches the concurrent map write.
	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			opt := Options{
				Source:     "file://" + filepath.ToSlash(srcDir),
				WorkingDir: srcDir,
				Logger:     log.WithPrefix("test"),
			}
			// Download error is irrelevant — the global mutation at the (unfixed)
			// line 74 happens before client.Get(), which is what we are testing.
			_ = Remote.download(context.Background(), opt, filepath.Join(t.TempDir(), "dst"))
		}()
	}
	wg.Wait()

	// The global map must not have been mutated by download().
	// Without the fix, line 74 overwrites this with &FileGetter{Copy: true}.
	require.Same(t, original, getter.Getters["file"],
		"download() must not mutate the package-global getter.Getters map — clone locally instead")
}
