package downloader

import (
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// backupDst renames dst aside so that go-getter can create it fresh.
// It returns a cleanup function that restores dst on error or removes the backup on success.
func backupDst(dst string) (cleanup func(), err error) {
	backup := dst + ".backup"
	_ = os.RemoveAll(backup)

	if err := os.Rename(dst, backup); errors.Is(err, os.ErrNotExist) {
		return func() {}, nil
	} else if err != nil {
		return nil, xerrors.Errorf("failed to rename dst: %w", err)
	}

	return func() {
		if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(backup, dst); err != nil {
				log.Warn("Failed to restore backup", log.FilePath(backup), log.Err(err))
			}
			return
		}
		if err := os.RemoveAll(backup); err != nil {
			log.Warn("Failed to remove backup", log.FilePath(backup), log.Err(err))
		}
	}, nil
}
