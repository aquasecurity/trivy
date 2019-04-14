package types

import (
	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/types"
)

type Scanner interface {
	UpdateDB() error
	ParseLockfile() ([]types.Library, error)
	Detect(string, *version.Version) ([]types.Vulnerability, error)
}
