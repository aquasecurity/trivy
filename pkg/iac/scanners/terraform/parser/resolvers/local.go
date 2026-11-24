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

func (r *localResolver) Resolve(_ context.Context, target fs.FS, opt Options) (Result, error) {
	if !opt.hasPrefix(".", "..") {
		return Result{}, ErrNotApplicable
	}
	joined := path.Clean(path.Join(opt.ModulePath, opt.Source))
	if _, err := fs.Stat(target, filepath.ToSlash(joined)); err == nil {
		opt.Logger.Debug("Module resolved locally",
			log.String("name", opt.Name), log.FilePath(joined),
		)
		return Result{FS: target, Dir: joined}, nil
	}

	clean := path.Clean(opt.Source)
	opt.Logger.Debug("Module resolved locally",
		log.String("name", opt.Name), log.FilePath(clean),
	)
	return Result{FS: target, Dir: clean}, nil
}
