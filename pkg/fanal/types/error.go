package types

import "errors"

var (
	InvalidURLPattern = errors.New("invalid url pattern")
	ErrNoRpmCmd       = errors.New("no rpm command")
)
