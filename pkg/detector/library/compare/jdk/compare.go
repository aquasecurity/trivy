// Package jdk compares JEP 322 OpenJDK runtime versions against OpenJDK advisories.
package jdk

import (
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer compares OpenJDK runtime versions.
type Comparer struct{}

// IsVulnerable checks if the runtime version is vulnerable to the advisory.
func (c Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, c.MatchVersion)
}

type parsedVersion struct {
	nums  []int
	build int
}

func parseVersion(s string) (parsedVersion, error) {
	s = strings.TrimSpace(s)
	base, buildStr, hasPlus := strings.Cut(s, "+")
	parts := strings.Split(base, ".")
	if len(parts) == 0 || parts[0] == "" {
		return parsedVersion{}, xerrors.Errorf("empty version %q", s)
	}
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return parsedVersion{}, xerrors.Errorf("invalid segment %q in %q: %w", p, s, err)
		}
		nums = append(nums, n)
	}
	for len(nums) > 1 && nums[len(nums)-1] == 0 {
		nums = nums[:len(nums)-1]
	}
	var build int
	if hasPlus && buildStr != "" {
		b, err := strconv.Atoi(buildStr)
		if err != nil {
			return parsedVersion{}, xerrors.Errorf("invalid build %q in %q: %w", buildStr, s, err)
		}
		build = b
	}
	return parsedVersion{nums: nums, build: build}, nil
}

func compareVersions(a, b parsedVersion) int {
	maxLen := max(len(a.nums), len(b.nums))
	for i := range maxLen {
		var av, bv int
		if i < len(a.nums) {
			av = a.nums[i]
		}
		if i < len(b.nums) {
			bv = b.nums[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.build < b.build:
		return -1
	case a.build > b.build:
		return 1
	default:
		return 0
	}
}

// MatchVersion checks whether an OpenJDK version satisfies a constraint expression.
func (Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	cur, err := parseVersion(currentVersion)
	if err != nil {
		return false, err
	}
	for orGroup := range strings.SplitSeq(constraint, "||") {
		orGroup = strings.TrimSpace(orGroup)
		if orGroup == "" {
			continue
		}
		groupOK := true
		for term := range strings.SplitSeq(orGroup, ",") {
			term = strings.TrimSpace(term)
			if term == "" {
				continue
			}
			ok, err := checkTerm(cur, term)
			if err != nil {
				return false, err
			}
			if !ok {
				groupOK = false
				break
			}
		}
		if groupOK {
			return true, nil
		}
	}
	return false, nil
}

func checkTerm(cur parsedVersion, term string) (bool, error) {
	op := "="
	rest := term
	for _, candidate := range []string{"<=", ">=", "==", "!=", "<", ">", "="} {
		if after, ok := strings.CutPrefix(term, candidate); ok {
			op = candidate
			rest = strings.TrimSpace(after)
			break
		}
	}
	target, err := parseVersion(rest)
	if err != nil {
		return false, err
	}
	cmp := compareVersions(cur, target)
	switch op {
	case "<":
		return cmp < 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">":
		return cmp > 0, nil
	case ">=":
		return cmp >= 0, nil
	case "!=":
		return cmp != 0, nil
	case "=", "==":
		return cmp == 0, nil
	default:
		return false, xerrors.Errorf("unsupported operator %q", op)
	}
}
