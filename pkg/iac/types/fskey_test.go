package types

import (
	"io/fs"
	"os"
	"testing"

	"github.com/liamg/memoryfs"

	"github.com/stretchr/testify/assert"
)

func Test_FSKey(t *testing.T) {

	systems := []fs.FS{
		os.DirFS("."),
		os.DirFS(".."),
		memoryfs.New(),
		memoryfs.New(),
	}

	keys := make(map[string]struct{})

	t.Run("uniqueness", func(t *testing.T) {
		for _, system := range systems {
			key := CreateFSKey(system)
			_, ok := keys[key]
			assert.False(t, ok, "filesystem keys should be unique")
			keys[key] = struct{}{}
		}
	})

	t.Run("reproducible", func(t *testing.T) {
		for _, system := range systems {
			key := CreateFSKey(system)
			_, ok := keys[key]
			assert.True(t, ok, "filesystem keys should be reproducible")
		}
	})
}
