package resolvers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-getter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

// TestDownloadDoesNotMutateGlobalGetters is a regression test for #10832.
//
// download() previously overrode the file getter by writing to the package-global
// getter.Getters map on every call. When modules are resolved concurrently that
// is a data race on the shared map (the Go runtime may abort with "concurrent map
// writes"). The fix builds a per-call copy of the getters, so the global map must
// be left untouched.
func TestDownloadDoesNotMutateGlobalGetters(t *testing.T) {
	fileGetter, ok := getter.Getters["file"].(*getter.FileGetter)
	require.True(t, ok)
	require.False(t, fileGetter.Copy, "precondition: the global file getter should not have Copy set")

	opt := Options{
		Source:     filepath.Join(t.TempDir(), "does-not-exist"),
		WorkingDir: t.TempDir(),
		Logger:     log.WithPrefix("test"),
	}
	// The download itself is expected to fail because the source does not exist;
	// we only care that it did not mutate the global getter.Getters map.
	_ = Remote.download(context.Background(), opt, filepath.Join(t.TempDir(), "dst"))

	fileGetter, ok = getter.Getters["file"].(*getter.FileGetter)
	require.True(t, ok)
	assert.False(t, fileGetter.Copy, "download() must not mutate the global getter.Getters map")
}
