package getter

import (
	"fmt"
	"github.com/klauspost/compress/zstd"
	"os"
	"path/filepath"
)

// ZstdDecompressor is an implementation of Decompressor that
// can decompress .zst files.
type ZstdDecompressor struct{}

func (d *ZstdDecompressor) Decompress(dst, src string, dir bool, umask os.FileMode) error {
	if dir {
		return fmt.Errorf("zstd-compressed files can only unarchive to a single file")
	}

	// If we're going into a directory we should make that first
	if err := os.MkdirAll(filepath.Dir(dst), mode(0755, umask)); err != nil {
		return err
	}

	// File first
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	// zstd compression is second
	zstdR, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zstdR.Close()

	// Copy it out
	return copyReader(dst, zstdR, 0622, umask)
}
