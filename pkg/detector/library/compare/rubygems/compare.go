package rubygems

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

var (
	platformReplacer = strings.NewReplacer(
		"-java", "",
		"-mswin32", "",
		"-mswin64", "",
		"-universal-mingw32", "",
		"-x64-mingw32", "",
		"-x86_64-mingw32", "",
		"-mingw32", "",
	)
)

// Comparer represents a comparer for RubyGems
type Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (r Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, r.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (r Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	// There are same packages for ruby and jruby. We need trim platform suffix
	// Otherwise suffix will recognize as pre-release version (https://semver.org/#spec-item-9)
	// e.g. https://rubygems.org/gems/puma/versions/5.6.4-java and https://rubygems.org/gems/puma/versions/5.6.4
	currentVersion = platformReplacer.Replace(currentVersion)
	v, err := gem.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("RubyGems version error (%s): %s", currentVersion, err)
	}

	c, err := gem.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("RubyGems constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
