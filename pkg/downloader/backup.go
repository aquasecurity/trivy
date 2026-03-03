package downloader

import (
	"errors"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

// backupDst renames dst aside so that go-getter can create it fresh.
// It returns a restore function that moves the backup back into place.
func backupDst(dst string) (restore func(), err error) {
	backup := dst + ".backup"
	_ = os.RemoveAll(backup)

	if err := os.Rename(dst, backup); errors.Is(err, os.ErrNotExist) {
		return func() {}, nil
	} else if err != nil {
		return nil, xerrors.Errorf("failed to rename dst: %w", err)
	}

	return func() {
		_ = os.RemoveAll(dst)
		if err := os.Rename(backup, dst); err != nil {
			log.Warn("Failed to restore backup", log.FilePath(backup), log.Err(err))
		}
	}, nil
}
