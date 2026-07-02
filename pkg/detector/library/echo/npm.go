package echo

import (
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// npmComparer compares npm package versions with Echo-aware ordering.
// npm follows SemVer, which excludes build metadata from precedence, so the
// standard npm comparer treats "2.14.2+echo.1" and "2.14.2+echo.2" as equal
// and cannot tell one Echo build from another. Echo publishes successive
// patched builds that differ only in the "+echo.N" build number, so SemVer
// ties are broken by N (a version without the suffix has N=0):
// 2.14.2 < 2.14.2+echo.1 < 2.14.2+echo.2 < 2.14.3.
type npmComparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n npmComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint:
// "||"-separated groups of comma-separated comparators, e.g.
// ">=1.2.3+echo.1, <1.2.3+echo.2 || 2.0.0+echo.1". A comparator without an
// operator is an exact match.
func (n npmComparer) matchVersion(currentVersion, constraint string) (bool, error) {
	ver, err := newEchoNpmVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("npm version error (%s): %w", currentVersion, err)
	}

	for _, group := range strings.Split(constraint, "||") {
		ok, err := matchComparators(ver, group)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func matchComparators(ver echoNpmVersion, group string) (bool, error) {
	for _, comparator := range strings.Split(group, ",") {
		comparator = strings.TrimSpace(comparator)
		if comparator == "" {
			continue
		}

		op := "="
		verStr := comparator
		for _, prefix := range []string{">=", "<=", "==", ">", "<", "="} {
			if strings.HasPrefix(comparator, prefix) {
				op = prefix
				verStr = strings.TrimSpace(strings.TrimPrefix(comparator, prefix))
				break
			}
		}

		other, err := newEchoNpmVersion(verStr)
		if err != nil {
			return false, xerrors.Errorf("npm constraint error (%s): %w", comparator, err)
		}

		var ok bool
		switch c := ver.compare(other); op {
		case "=", "==":
			ok = c == 0
		case ">":
			ok = c > 0
		case ">=":
			ok = c >= 0
		case "<":
			ok = c < 0
		case "<=":
			ok = c <= 0
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// echoNpmVersion is an npm version plus its Echo build number.
type echoNpmVersion struct {
	npm.Version
	echoBuild int
}

func newEchoNpmVersion(s string) (echoNpmVersion, error) {
	v, err := npm.NewVersion(s)
	if err != nil {
		return echoNpmVersion{}, err
	}
	var build int
	if m := echoLocalSegmentRe.FindStringSubmatch(s); m != nil {
		build, err = strconv.Atoi(m[1])
		if err != nil {
			return echoNpmVersion{}, xerrors.Errorf("invalid echo build number (%s): %w", s, err)
		}
	}
	return echoNpmVersion{Version: v, echoBuild: build}, nil
}

func (v echoNpmVersion) compare(other echoNpmVersion) int {
	if c := v.Version.Compare(other.Version); c != 0 {
		return c
	}
	switch {
	case v.echoBuild < other.echoBuild:
		return -1
	case v.echoBuild > other.echoBuild:
		return 1
	}
	return 0
}
