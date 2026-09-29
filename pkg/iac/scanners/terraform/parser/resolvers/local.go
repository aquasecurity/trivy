package resolvers

import (
	"context"
	"io/fs"
	"path"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/log"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, target fs.FS, opt Options) (filesystem fs.FS, prefix, downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(".", "..") {
		return nil, "", "", false, nil
	}
	joined := path.Clean(path.Join(opt.ModulePath, opt.Source))
	if _, err := fs.Stat(target, filepath.ToSlash(joined)); err == nil {
		opt.Logger.Debug("Module resolved locally",
			log.String("name", opt.Name), log.FilePath(joined),
		)
		return target, "", joined, true, nil
	}

	clean := path.Clean(opt.Source)
	opt.Logger.Debug("Module resolved locally",
		log.String("name", opt.Name), log.FilePath(clean),
	)
	return target, "", clean, true, nil
}
