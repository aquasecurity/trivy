package downloader

import (
	"context"
	"maps"
	"os"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

// DownloadToTempDir downloads the configured source to a temp dir.
func DownloadToTempDir(ctx context.Context, url string, insecure bool) (string, error) {
	tempDir, err := os.MkdirTemp("", "trivy-download")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if err = Download(ctx, url, tempDir, pwd, insecure); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tempDir, nil
}

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst, pwd string, insecure bool) error {
	// go-getter doesn't allow the dst directory already exists if the src is directory.
	_ = os.RemoveAll(dst)

	var opts []getter.ClientOption
	if insecure {
		opts = append(opts, getter.WithInsecure())
	}

	// Clone the global map so that it will not be accessed concurrently.
	getters := maps.Clone(getter.Getters)

	// Overwrite the file getter so that a file will be copied
	getters["file"] = &getter.FileGetter{Copy: true}

	// Since "httpGetter" is a global pointer and the state is shared,
	// once it is executed without "WithInsecure()",
	// it cannot enable WithInsecure() afterwards because its state is preserved.
	// cf. https://github.com/hashicorp/go-getter/blob/5a63fd9c0d5b8da8a6805e8c283f46f0dacb30b3/get.go#L63-L65
	httpGetter := &getter.HttpGetter{Netrc: true}
	getters["http"] = httpGetter
	getters["https"] = httpGetter

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: getters,
		Mode:    getter.ClientModeAny,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	return nil
}
