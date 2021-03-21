package downloader

import (
	"context"
	"os"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

// DownloadToTempDir downloads the configured source to a temp dir.
func DownloadToTempDir(ctx context.Context, url string) (string, error) {
	tempDir, err := os.MkdirTemp("", "trivy-plugin")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if err = Download(ctx, url, tempDir, pwd); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tempDir, nil
}

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst, pwd string) error {
	// go-getter doesn't allow the dst directory already exists if the src is directory.
	_ = os.RemoveAll(dst)

	var opts []getter.ClientOption

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	return nil
}
