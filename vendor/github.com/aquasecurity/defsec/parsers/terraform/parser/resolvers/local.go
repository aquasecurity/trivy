package resolvers

import (
	"context"
	"fmt"
	"os"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, opt Options) (downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(fmt.Sprintf(".%c", os.PathSeparator), fmt.Sprintf("..%c", os.PathSeparator)) {
		return "", false, nil
	}
	opt.Debug("Module '%s' resolving via local...", opt.Name)
	return opt.Source, true, nil
}
