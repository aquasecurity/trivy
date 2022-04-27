package resolvers

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

type remoteResolver struct {
	count int32
}

var Remote = &remoteResolver{
	count: 0,
}

func (r *remoteResolver) incrementCount(o Options) {
	o.Debug("Incrementing the download counter")
	atomic.CompareAndSwapInt32(&r.count, int32(r.count), int32(r.count+1))
	o.Debug("Download counter is now %d", r.count)
}

func (r *remoteResolver) GetDownloadCount() int {
	return int(r.count)
}

func (r *remoteResolver) Resolve(ctx context.Context, opt Options) (downloadPath string, applies bool, err error) {
	if !opt.hasPrefix("github.com/", "bitbucket.org/", "s3:", "git@", "git:", "hg:", "https:", "gcs:") {
		return "", false, nil
	}

	if !opt.AllowDownloads {
		return "", false, nil
	}

	cacheDir := getCacheDir(opt.WorkingDir, opt.Name)
	if err := r.download(ctx, opt, cacheDir); err != nil {
		return "", true, err
	}
	r.incrementCount(opt)
	opt.Debug("Successfully downloaded %s from %s", opt.Name, opt.Source)
	if err := writeCacheRecord(cacheDir, opt.Source, opt.Version); err != nil {
		return "", true, err
	}
	return cacheDir, true, nil
}

func (r *remoteResolver) download(ctx context.Context, opt Options, dst string) error {
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Dir(dst), 0o666); err != nil {
		return err
	}

	var opts []getter.ClientOption

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     opt.Source,
		Dst:     dst,
		Pwd:     opt.WorkingDir,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	opt.Debug("Module '%s' resolving via remote download...", opt.Name)
	return nil
}
