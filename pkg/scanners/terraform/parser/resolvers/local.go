package resolvers

import (
	"context"
	"io/fs"
	"path/filepath"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, target fs.FS, opt Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(".", "..") {
		return nil, "", "", false, nil
	}
	joined := filepath.Clean(filepath.Join(opt.ModulePath, opt.Source))
	if _, err := fs.Stat(target, filepath.ToSlash(joined)); err == nil {
		opt.Debug("Module '%s' resolved locally to %s", opt.Name, joined)
		return target, "", joined, true, nil
	}

	clean := filepath.Clean(opt.Source)
	opt.Debug("Module '%s' resolved locally to %s", opt.Name, clean)
	return target, "", clean, true, nil
}
