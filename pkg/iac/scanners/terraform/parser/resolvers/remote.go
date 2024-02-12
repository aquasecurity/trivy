package resolvers

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/hashicorp/go-getter"
)

type remoteResolver struct {
	count int32
}

var Remote = &remoteResolver{
	count: 0,
}

func (r *remoteResolver) incrementCount(o Options) {
	o.Debug("Incrementing the download counter")
	atomic.CompareAndSwapInt32(&r.count, r.count, r.count+1)
	o.Debug("Download counter is now %d", r.count)
}

func (r *remoteResolver) GetDownloadCount() int {
	return int(atomic.LoadInt32(&r.count))
}

func (r *remoteResolver) Resolve(ctx context.Context, _ fs.FS, opt Options) (filesystem fs.FS, prefix, downloadPath string, applies bool, err error) {
	if !opt.hasPrefix("github.com/", "bitbucket.org/", "s3:", "git@", "git:", "hg:", "https:", "gcs:") {
		return nil, "", "", false, nil
	}

	if !opt.AllowDownloads {
		return nil, "", "", false, nil
	}

	key := cacheKey(opt.OriginalSource, opt.OriginalVersion, opt.RelativePath)
	opt.Debug("Storing with cache key %s", key)

	baseCacheDir, err := locateCacheDir()
	if err != nil {
		return nil, "", "", true, fmt.Errorf("failed to locate cache directory: %w", err)
	}
	cacheDir := filepath.Join(baseCacheDir, key)
	if err := r.download(ctx, opt, cacheDir); err != nil {
		return nil, "", "", true, err
	}

	r.incrementCount(opt)
	opt.Debug("Successfully downloaded %s from %s", opt.Name, opt.Source)
	opt.Debug("Module '%s' resolved via remote download.", opt.Name)
	return os.DirFS(cacheDir), opt.Source, filepath.Join(".", opt.RelativePath), true, nil
}

func (r *remoteResolver) download(ctx context.Context, opt Options, dst string) error {
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}

	var opts []getter.ClientOption

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	opt.Debug("Downloading %s...", opt.Source)

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
		return fmt.Errorf("failed to download: %w", err)
	}

	return nil
}

func (r *remoteResolver) GetSourcePrefix(source string) string {
	return source
}
