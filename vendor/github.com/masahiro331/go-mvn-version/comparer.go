package version

import (
	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"
)

type Comparer interface {
	Check(v Version) bool
}

func NewComparer(v string) (Comparer, error) {
	var errs error

	c, err := NewConstraints(v)
	if err == nil {
		return c, nil
	}
	errs = multierror.Append(errs, err)

	r, err := NewRequirements(v)
	if err == nil {
		return r, nil
	}
	errs = multierror.Append(errs, err)

	return nil, xerrors.Errorf("failed to new comparer: %w", errs)
}
