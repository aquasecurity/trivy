package os_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

func TestNewRoot_CreatesAndConfines(t *testing.T) {
	base := filepath.Join(t.TempDir(), "root")

	r, err := xos.NewRoot(base)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	assert.DirExists(t, base)       // NewRoot creates the directory
	assert.Equal(t, base, r.Name()) // promoted os.Root.Name()

	// Confined operations (promoted from os.Root) reject escaping names.
	_, err = r.Stat("../escape")
	require.Error(t, err)
	require.Error(t, r.MkdirAll("../escape", 0o700))
}

func TestRoot_Join(t *testing.T) {
	base := filepath.Join(t.TempDir(), "root")
	r, err := xos.NewRoot(base)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	// An existing directory resolves to its path under the root.
	require.NoError(t, r.MkdirAll("plugin", 0o700))
	got, err := r.Join("plugin")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "plugin"), got)

	// A not-yet-existing local name is allowed (the caller creates it later).
	got, err = r.Join("does-not-exist")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "does-not-exist"), got)

	// Escaping names are rejected, including escapes hidden behind a missing
	// component: os.Root.Stat reports those as ErrNotExist, so filepath.IsLocal
	// is what catches them.
	for _, name := range []string{"../escape", "/etc", "..", "a/../../etc", "missing/../../etc"} {
		_, err := r.Join(name)
		require.Error(t, err, name)
	}

	// A symlink that stays within the root is allowed.
	require.NoError(t, os.WriteFile(filepath.Join(base, "target.txt"), []byte("x"), 0o600))
	require.NoError(t, os.Symlink("target.txt", filepath.Join(base, "inside")))
	got, err = r.Join("inside")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "inside"), got)

	// An existing symlink that points outside the root is rejected.
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(base, "link")))
	_, err = r.Join("link")
	require.Error(t, err)
}
