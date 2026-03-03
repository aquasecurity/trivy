package downloader

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// renameDir renames the source directory to the destination directory.
// This is used to move the downloaded content from a temp dir to the final destination.
// On Windows, os.Rename doesn't work if the destination already exists,
// so we need to copy the content and remove the source manually.
func renameDir(sourcePath, destPath string) error {
	// Create destination directory
	err := os.MkdirAll(destPath, 0755)
	if err != nil {
		return fmt.Errorf("couldn't create dest directory: %v", err)
	}

	// Walk through source directory
	err = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(destPath, relPath)
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}
		// Copy file
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer dstFile.Close()
		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("couldn't copy directory: %v", err)
	}
	// Remove source directory
	err = os.RemoveAll(sourcePath)
	if err != nil {
		return fmt.Errorf("couldn't remove source directory: %v", err)
	}
	return nil
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
		_ = renameDir(backup, dst)
	}
}
