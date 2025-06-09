package types

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
)

func CreateFSKey(filesystem fs.FS) string {
	if filesystem == nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s%#[1]v", filesystem))))
}
