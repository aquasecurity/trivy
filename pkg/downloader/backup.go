package downloader

import (
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// backupDst renames dst aside so that go-getter can create it fresh.
// It returns a cleanup function: call it with restore=true to move the backup
// back into place (e.g. on a 304), or restore=false to drop it.
func backupDst(dst string) (cleanup func(restore bool), err error) {
	backup := dst + ".backup"
	_ = os.RemoveAll(backup)

	if err := os.Rename(dst, backup); errors.Is(err, os.ErrNotExist) {
		return func(bool) {}, nil
	} else if err != nil {
		return nil, xerrors.Errorf("failed to rename dst: %w", err)
	}

	return func(restore bool) {
		if restore {
			_ = os.RemoveAll(dst)
			if err := os.Rename(backup, dst); err != nil {
				log.Warn("Failed to restore backup", log.FilePath(backup), log.Err(err))
			}
		}
		// After a successful restore the rename already consumed the backup,
		// so this is a no-op; otherwise it drops the unused backup.
		_ = os.RemoveAll(backup)
	}, nil
}
