package resolvers

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-getter"

	"github.com/aquasecurity/trivy/pkg/log"
)

type remoteResolver struct {
	count atomic.Int32
}

var Remote = &remoteResolver{}

// Disable git's interactive credential prompt so that downloading a module
// from a repository that requires authentication fails fast instead of
// hanging. GIT_TERMINAL_PROMPT is process-global, so it is set once for the
// lifetime of the process: setting and restoring it around each download
// races with concurrent downloads. See #10833.
var disableGitTerminalPrompt = sync.OnceValue(func() error {
	return os.Setenv("GIT_TERMINAL_PROMPT", "0")
})

func (r *remoteResolver) incrementCount(o Options) {

	r.count.Add(1)
	o.Logger.Debug("Incrementing the download counter", log.Int("count", int(r.count.Load())))
}

func (r *remoteResolver) GetDownloadCount() int {
	return int(r.count.Load())
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

	// Use a copy of the default getters with the file getter overridden to
	// copy files, so that concurrent download calls don't write to the
	// package-global getter.Getters map. See #10832.
	getters := maps.Clone(getter.Getters)
	getters["file"] = &getter.FileGetter{Copy: true}

	opt.Logger.Debug("Downloading module", log.String("source", opt.Source))

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     opt.Source,
		Dst:     dst,
		Pwd:     opt.WorkingDir,
		Getters: getters,
		Mode:    getter.ClientModeAny,
	}

	if err := disableGitTerminalPrompt(); err != nil {
		opt.Logger.Error("Failed to set env", log.String("name", "GIT_TERMINAL_PROMPT"), log.Err(err))
	}

	if err := client.Get(); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	return nil
}

func (r *remoteResolver) GetSourcePrefix(source string) string {
	return source
}
