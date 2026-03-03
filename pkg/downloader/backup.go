//go:build !windows

package downloader

import (
	"os"
)

// renameDir renames the source directory to the destination directory.
// This is used to move the downloaded content from a temp dir to the final destination.
// On Windows, os.Rename doesn't work if the destination already exists,
// so we need to copy the content and remove the source manually.
func renameDir(sourcePath, destPath string) error {
	return os.Rename(sourcePath, destPath)
}

// removeBackup remove backup once we no longer need it.
func removeBackup(backup string) {
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
}

// restoreBackup put backup back as dst on 304 or download failure.
func restoreBackup(backup, dst string) {
	if backup != "" {
		_ = os.RemoveAll(dst) // remove any partial dst left by a failed download
		_ = os.Rename(backup, dst)
	}
}
