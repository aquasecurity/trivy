//go:build !windows
// +build !windows

package resolvers

import (
	"os"
	"syscall"
)

func isWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	if !info.IsDir() {
		return false
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return false
	}

	var stat syscall.Stat_t
	if err = syscall.Stat(path, &stat); err != nil {
		return false
	}

	if uint32(os.Geteuid()) != stat.Uid {
		return false
	}

	return true
}
