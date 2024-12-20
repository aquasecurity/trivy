package resolvers

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/hashicorp/go-getter"

	"github.com/aquasecurity/trivy/pkg/log"
)

type remoteResolver struct {
	count int32
}

var Remote = &remoteResolver{
	count: 0,
}

func (r *remoteResolver) incrementCount(o Options) {

	atomic.CompareAndSwapInt32(&r.count, r.count, r.count+1)
	o.Logger.Debug("Incrementing the download counter", log.Int("count", int(r.count)))
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

	origSrc, subdir := splitPackageSubdirRaw(opt.OriginalSource)
	key := cacheKey(origSrc, opt.OriginalVersion)
	opt.Logger.Debug("Caching module", log.String("key", key))

	baseCacheDir, err := locateCacheDir(opt.CacheDir)
	if err != nil {
		return nil, "", "", true, fmt.Errorf("failed to locate cache directory: %w", err)
	}

	cacheDir := filepath.Join(baseCacheDir, key)

	src, _ := splitPackageSubdirRaw(opt.Source)

	opt.Source = src
	if err := r.download(ctx, opt, cacheDir); err != nil {
		return nil, "", "", true, err
	}

	r.incrementCount(opt)
	opt.Logger.Debug("Successfully resolve module via remote download",
		log.String("name", opt.Name),
		log.String("source", opt.OriginalSource),
	)
	return os.DirFS(cacheDir), opt.OriginalSource, subdir, true, nil
}

func (r *remoteResolver) download(ctx context.Context, opt Options, dst string) error {
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	opt.Logger.Debug("Downloading module", log.String("source", opt.Source))

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     opt.Source,
		Dst:     dst,
		Pwd:     opt.WorkingDir,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
	}

	terminalPrompt := os.Getenv("GIT_TERMINAL_PROMPT")
	if err := os.Setenv("GIT_TERMINAL_PROMPT", "0"); err != nil {
		opt.Logger.Error("Failed to set env", log.String("name", "GIT_TERMINAL_PROMPT"), log.Err(err))
	} else {
		defer os.Setenv("GIT_TERMINAL_PROMPT", terminalPrompt)
	}

	if err := client.Get(); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	return nil
}

func (r *remoteResolver) GetSourcePrefix(source string) string {
	return source
}
