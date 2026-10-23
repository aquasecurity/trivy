package compare

import (
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Comparer is an interface for version comparison
type Comparer interface {
	IsVulnerable(currentVersion string, advisory dbTypes.Advisory) bool
}

type matchVersion func(currentVersion, constraint string) (bool, error)

// IsVulnerable checks if the package version is vulnerable to the advisory.
func IsVulnerable(pkgVer string, advisory dbTypes.Advisory, match matchVersion) bool {
	// If one of vulnerable/patched versions is empty, we should detect it anyway.
	if slices.Contains(append(advisory.VulnerableVersions, advisory.PatchedVersions...), "") {
		return true
	}
	var matched bool
	var err error

	if len(advisory.VulnerableVersions) != 0 {
		matched, err = match(pkgVer, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil {
			log.Warn("Version matching error", log.Err(err))
			return false
		} else if !matched {
			// the version is not vulnerable
			return false
		}
	}

	secureVersions := append(advisory.PatchedVersions, advisory.UnaffectedVersions...)
	if len(secureVersions) == 0 {
		// the version matches vulnerable versions and patched/unaffected versions are not provided
		// or all values are empty
		return matched
	}

	matched, err = match(pkgVer, strings.Join(secureVersions, " || "))
	if err != nil {
		log.Warn("Version matching error", log.Err(err))
		return false
	}
	return !matched
}

// GenericOption is a functional option for GenericComparer.
type GenericOption func(*GenericComparer)

// WithBuildMetadata makes build metadata significant when checking constraints.
// SemVer ignores it for precedence (https://semver.org/#spec-item-10); with this
// option versions are ordered following node-semver's compareBuild:
// "1.2.3" < "1.2.3+build.1" < "1.2.3+build.2" < "1.2.4".
func WithBuildMetadata() GenericOption {
	return func(c *GenericComparer) {
		c.withBuildMetadata = true
	}
}

// GenericComparer represents a comparer for semver-like versioning
type GenericComparer struct {
	withBuildMetadata bool
}

// NewGenericComparer returns a new GenericComparer with the given options.
func NewGenericComparer(opts ...GenericOption) GenericComparer {
	c := GenericComparer{}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (v GenericComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return IsVulnerable(ver, advisory, v.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (v GenericComparer) matchVersion(currentVersion, constraint string) (bool, error) {
	ver, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("version error (%s): %s", currentVersion, err)
	}

	var opts []version.ConstraintOption
	if v.withBuildMetadata {
		opts = append(opts, version.WithBuildMetadataOrder(version.BuildMetadataOrderNodeSemver))
	}

	c, err := version.NewConstraints(constraint, opts...)
	if err != nil {
		return false, xerrors.Errorf("constraint error (%s): %s", currentVersion, err)
	}

	return c.Check(ver), nil
}
