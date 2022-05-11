package version

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"
)

var (
	requirementRegexp     *regexp.Regexp
	softRequirementRegexp *regexp.Regexp
)

const (
	MINVersion       = "-----1"
	MAXVersion       = "99999999999999999999"
	requirementRegex = `(` +
		`[\[\(]` +
		`[0-9A-Za-z\-\.,]+` +
		`[\]\)]` +
		`)`

	softRequirementRegex = `^[0-9A-Za-z\-~\.]+$`
)

func init() {
	requirementRegexp = regexp.MustCompile(requirementRegex)
	softRequirementRegexp = regexp.MustCompile(softRequirementRegex)
}

type Requirements struct {
	requirements [][]requirement
}

type requirement struct {
	version  Version
	operator operatorFunc
	original string
}

// NewRequirements is return Requirement
// [1.0.0], [1.0.1]	=> []requirement{"[1.0.0]","[1.0.1]"}
// [1.0.0]		=> []requirement{"[1.0.0]"}
func NewRequirements(v string) (Requirements, error) {
	// trimSpace "[ , 1.0.0]" => "[,1.0.0]"
	v = trimSpaces(v)

	var rss [][]requirement
	if softRequirementRegexp.MatchString(v) {
		r, err := newRequirement(v)
		if err != nil {
			return Requirements{}, xerrors.Errorf("improper soft requirements: %v", v)
		}
		return Requirements{
			requirements: append(rss, []requirement{r}),
		}, nil
	}

	// Normalization
	// "(,1.0.0)"			=> "(MIN, 1.0.0)"
	// "(1.0.0,)"			=> "[1.0.0, MAX)"
	// "[1.0.0]"			=> "[1.0.0, 1.0.0]"
	// "(1.0.0]"			=> "[1.0.0, 1.0.0]"
	// "[,1.0.0],[1.0.0,1.1]"	=> "[,1.0.0]", "[1.0.0,1.1]"
	requirements := requirementRegexp.FindAllString(v, -1)
	if len(requirements) == 0 {
		return Requirements{}, xerrors.Errorf("improper requirements: %v", requirements)
	}

	for _, r := range requirements {
		var rs []requirement
		ss := strings.Split(r, ",")
		if len(ss) > 2 {
			return Requirements{}, xerrors.Errorf("improper requirement length: %v", r)
		}
		if len(ss) == 1 && checkEqualOperator(ss[0]) {
			nr, err := newRequirement(ss[0])
			if err != nil {
				return Requirements{}, xerrors.Errorf("failed to parse requirement: %w", err)
			}
			rss = append(rss, append(rs, nr))
			continue
		}

		// "[,1.0.0]" => []string{"[MIN", "1.0.0]"}
		if len(ss[0]) == 1 {
			ss[0] = ss[0] + MINVersion
		}

		// "[,1.0.0]" => []string{"[1.0.0", "MAX]"}
		if len(ss[1]) == 1 {
			ss[1] = MAXVersion + ss[1]
		}

		for _, single := range ss {
			nr, err := newRequirement(single)
			if err != nil {
				return Requirements{}, xerrors.Errorf("failed to parse requirement: %w", err)
			}
			rs = append(rs, nr)
		}
		rss = append(rss, rs)
	}

	return Requirements{
		requirements: rss,
	}, nil
}

func newRequirement(r string) (requirement, error) {
	var v Version
	var err error
	var operator operatorFunc
	switch {
	case checkEqualOperator(r):
		v, err = NewVersion(r[1 : len(r)-2])
		operator = requirementEqual
	case strings.HasPrefix(r, "["):
		v, err = NewVersion(strings.TrimPrefix(r, "["))
		operator = requirementGreaterThanEqual
	case strings.HasPrefix(r, "("):
		v, err = NewVersion(strings.TrimPrefix(r, "("))
		operator = requirementGreaterThan
	case strings.HasSuffix(r, "]"):
		v, err = NewVersion(strings.TrimSuffix(r, "]"))
		operator = requirementLessThanEqual
	case strings.HasSuffix(r, ")"):
		v, err = NewVersion(strings.TrimSuffix(r, ")"))
		operator = requirementLessThan
	default: // soft requirement
		v, err = NewVersion(r)
		operator = requirementSoftRequirement
	}
	if err != nil {
		return requirement{}, xerrors.Errorf("failed to new version: %w", err)
	}
	return requirement{
		version:  v,
		operator: operator,
		original: r,
	}, nil
}

func (rs Requirements) Check(v Version) bool {
	for _, r := range rs.requirements {
		if andRequirementCheck(v, r) {
			return true
		}
	}
	return false
}

func andRequirementCheck(v Version, requirements []requirement) bool {
	for _, c := range requirements {
		if !c.check(v) {
			return false
		}
	}
	return true
}

func (r requirement) check(v Version) bool {
	return r.operator(v, r.version)
}

func trimSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// checkEqualOperator check equal operation.
// e.g.
// "[1.0.0]" => "== 1.0.0"
// "(1.0.0)" => "== 1.0.0"
func checkEqualOperator(r string) bool {
	if (strings.HasPrefix(r, "[") || strings.HasPrefix(r, "(")) &&
		(strings.HasSuffix(r, "]") || strings.HasSuffix(r, ")")) {
		return true
	}
	return false
}

//-------------------------------------------------------------------
// Requirement functions
//-------------------------------------------------------------------

// soft requirement always return true
func requirementSoftRequirement(v, c Version) bool {
	return true
}

func requirementEqual(v, c Version) bool {
	return v.Equal(c)
}

func requirementGreaterThan(v, c Version) bool {
	return v.GreaterThan(c)
}

func requirementLessThan(v, c Version) bool {
	return v.LessThan(c)
}

func requirementGreaterThanEqual(v, c Version) bool {
	return v.GreaterThanOrEqual(c)
}

func requirementLessThanEqual(v, c Version) bool {
	return v.LessThanOrEqual(c)
}
