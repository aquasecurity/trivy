// Package jdk compares JEP 322 OpenJDK runtime versions against OpenJDK advisories.
package jdk

import (
	"cmp"
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
	nums     []int
	pre      string
	build    int
	hasBuild bool
}

func parseVersion(s string) (parsedVersion, error) {
	s = strings.TrimSpace(s)
	beforePlus, afterPlus, hasPlus := strings.Cut(s, "+")
	base, preAndOpt, hasDash := strings.Cut(beforePlus, "-")

	parts := strings.Split(base, ".")
	if len(parts) == 0 || parts[0] == "" {
		return parsedVersion{}, xerrors.Errorf("empty version %q", s)
	}
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		if !isAllDigits(p) {
			return parsedVersion{}, xerrors.Errorf("invalid segment %q in %q", p, s)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return parsedVersion{}, xerrors.Errorf("invalid segment %q in %q: %w", p, s, err)
		}
		nums = append(nums, n)
	}
	for len(nums) > 1 && nums[len(nums)-1] == 0 {
		nums = nums[:len(nums)-1]
	}

	var pre string
	if hasDash {
		pre, _, _ = strings.Cut(preAndOpt, "-")
		if pre == "" {
			return parsedVersion{}, xerrors.Errorf("empty pre-release in %q", s)
		}
	}

	var build int
	var hasBuild bool
	if hasPlus {
		buildStr, _, _ := strings.Cut(afterPlus, "-")
		if buildStr != "" {
			if !isAllDigits(buildStr) {
				return parsedVersion{}, xerrors.Errorf("invalid build %q in %q", buildStr, s)
			}
			b, err := strconv.Atoi(buildStr)
			if err != nil {
				return parsedVersion{}, xerrors.Errorf("invalid build %q in %q: %w", buildStr, s, err)
			}
			build = b
			hasBuild = true
		}
	}

	return parsedVersion{nums: nums, pre: pre, build: build, hasBuild: hasBuild}, nil
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
		if c := cmp.Compare(av, bv); c != 0 {
			return c
		}
	}
	if c := comparePre(a.pre, b.pre); c != 0 {
		return c
	}
	switch {
	case !a.hasBuild && !b.hasBuild:
		return 0
	case !a.hasBuild:
		return -1
	case !b.hasBuild:
		return 1
	default:
		return cmp.Compare(a.build, b.build)
	}
}

func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1 // GA > pre-release
	}
	if b == "" {
		return -1 // pre-release < GA
	}
	aNum := isAllDigits(a)
	bNum := isAllDigits(b)
	switch {
	case aNum && bNum:
		return compareNumericStrings(a, b)
	case aNum:
		return -1 // JEP 322: numeric pre-release < non-numeric pre-release
	case bNum:
		return 1
	default:
		return cmp.Compare(a, b)
	}
}

func compareNumericStrings(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return cmp.Compare(a, b)
}

func isAllDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
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
