package types

import (
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/set"
)

func Test_FSKey(t *testing.T) {

	systems := []fs.FS{
		os.DirFS("."),
		os.DirFS(".."),
		fstest.MapFS{},
		mapfs.New(),
		mapfs.New(),
	}

	keys := set.New[string]()

	t.Run("uniqueness", func(t *testing.T) {
		for _, system := range systems {
			key := CreateFSKey(system)
			assert.False(t, keys.Contains(key), "filesystem keys should be unique")
			keys.Append(key)
		}
	})

	t.Run("reproducible", func(t *testing.T) {
		for _, system := range systems {
			key := CreateFSKey(system)
			assert.True(t, keys.Contains(key), "filesystem keys should be reproducible")
		}
	})
}
