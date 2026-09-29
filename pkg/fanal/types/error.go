package types

import "golang.org/x/xerrors"

var (
	InvalidURLPattern = xerrors.New("invalid url pattern")
	ErrNoRpmCmd       = xerrors.New("no rpm command")
)
