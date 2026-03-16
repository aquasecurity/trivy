package pep440

import (
	"golang.org/x/xerrors"

	version "github.com/aquasecurity/go-pep440-version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Option is a functional option for Comparer.
type Option func(*Comparer)

// AllowLocalSpecifier allows local version labels in specifiers (constraints) and enables
// strict local segment matching. Without this option, local labels in specifiers cause a
// parse error, and local segments of the candidate version are ignored in comparisons
// (e.g. "4.2.8+sp1" matches "== 4.2.8"). With this option, specifiers like
// ">= 4.2.8+sp1, < 4.2.8+sp999" are valid and "4.2.8+sp1" does not match "== 4.2.8".
func AllowLocalSpecifier() Option {
	return func(c *Comparer) {
		c.allowLocalSpecifier = true
	}
}

// Comparer represents a comparer for PEP 440
type Comparer struct {
	allowLocalSpecifier bool
}

// NewComparer returns a new Comparer with the given options.
func NewComparer(opts ...Option) Comparer {
	c := Comparer{}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (n Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("python version error (%s): %s", currentVersion, err)
	}

	opts := []version.SpecifierOption{version.WithPreRelease(true)}
	if n.allowLocalSpecifier {
		opts = append(opts, version.AllowLocalSpecifier(true))
	}

	c, err := version.NewSpecifiers(constraint, opts...)
	if err != nil {
		return false, xerrors.Errorf("python constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
