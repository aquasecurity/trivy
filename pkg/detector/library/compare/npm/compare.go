package npm

import (
	"golang.org/x/xerrors"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Option is a functional option for Comparer.
type Option func(*Comparer)

// WithBuildMetadata makes build metadata significant when checking constraints.
// SemVer ignores it for precedence (https://semver.org/#spec-item-10); with this
// option versions are ordered following node-semver's compareBuild:
// "1.2.3" < "1.2.3+build.1" < "1.2.3+build.2" < "1.2.4".
func WithBuildMetadata() Option {
	return func(c *Comparer) {
		c.withBuildMetadata = true
	}
}

// Comparer represents a comparer for npm
type Comparer struct {
	withBuildMetadata bool
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
	return compare.IsVulnerable(ver, advisory, n.MatchVersion)
}

// MatchVersion checks if the package version satisfies the given constraint.
func (n Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := npm.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("npm version error (%s): %s", currentVersion, err)
	}

	opts := []npm.ConstraintOption{npm.WithPreRelease(true)}
	if n.withBuildMetadata {
		opts = append(opts, npm.WithBuildMetadata(true))
	}

	c, err := npm.NewConstraints(constraint, opts...)
	if err != nil {
		return false, xerrors.Errorf("npm constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
