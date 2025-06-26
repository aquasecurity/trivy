package version

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"
)

// operatorFunc defines the signature for constraint operator functions
type operatorFunc func(v, c string, comparer Comparer) (bool, error)

// constraintOperators maps operator strings to their corresponding functions
var constraintOperators = map[string]operatorFunc{
	"":   constraintEqual,
	"=":  constraintEqual,
	"==": constraintEqual,
	"!=": constraintNotEqual,
	">":  constraintGreaterThan,
	"<":  constraintLessThan,
	">=": constraintGreaterThanEqual,
	"<=": constraintLessThanEqual,
}

// constraintRegex matches constraint patterns like ">=1.2.3", "<2.0.0", "==1.0.0"
// Version can contain numbers, dots, hyphens, plus signs, tildes, colons, and alphanumeric characters
var constraintRegex = regexp.MustCompile(`^(>=|<=|>|<|==|!=|=)?\s*([0-9]+[0-9a-zA-Z.\-+~:_]*)$`)

// constraint represents a single version constraint
type constraint struct {
	version  string
	operator operatorFunc
	original string
}

// Constraints represents a collection of constraints with a comparer
type Constraints struct {
	constraints []*constraint
	comparer    Comparer
}

// NewConstraints creates a new Constraints from a constraint string and comparer
// Multiple constraints can be separated by commas or spaces
func NewConstraints(constraints string, comparer Comparer) (*Constraints, error) {
	if constraints == "" {
		return nil, xerrors.New("constraints string is empty")
	}

	var cs []*constraint
	constraintList := splitConstraints(constraints)
	for _, constraintStr := range constraintList {
		constraintStr = strings.TrimSpace(constraintStr)
		if constraintStr == "" {
			continue
		}

		c, err := newConstraint(constraintStr)
		if err != nil {
			return nil, xerrors.Errorf("invalid constraint '%s': %w", constraintStr, err)
		}

		cs = append(cs, c)
	}

	return &Constraints{
		constraints: cs,
		comparer:    comparer,
	}, nil
}

// splitConstraints splits constraint string by comma or space, preferring comma
func splitConstraints(constraints string) []string {
	// If contains comma, split by comma
	if strings.Contains(constraints, ",") {
		return strings.Split(constraints, ",")
	}
	// Otherwise, split by spaces
	return strings.Fields(constraints)
}

// newConstraint creates a new constraint from a constraint string
func newConstraint(constraintStr string) (*constraint, error) {
	constraintStr = strings.TrimSpace(constraintStr)
	matches := constraintRegex.FindStringSubmatch(constraintStr)
	if len(matches) != 3 {
		return nil, xerrors.Errorf("invalid constraint format: %s", constraintStr)
	}

	op := matches[1]
	version := strings.TrimSpace(matches[2])

	operator, ok := constraintOperators[op]
	if !ok {
		return nil, xerrors.Errorf("unsupported operator: %s", op)
	}

	return &constraint{
		version:  version,
		operator: operator,
		original: constraintStr,
	}, nil
}

// Check returns true if the given version satisfies the constraint
func (c *constraint) check(version string, comparer Comparer) (bool, error) {
	return c.operator(version, c.version, comparer)
}

// String returns the original constraint string
func (c *constraint) String() string {
	return c.original
}

// Check returns true if the given version satisfies any of the constraints
// Multiple constraints are combined with AND logic
func (cs *Constraints) Check(version string) (bool, error) {
	if version == "" {
		return false, xerrors.New("version is empty")
	}

	if len(cs.constraints) == 0 {
		return false, xerrors.New("no constraints specified")
	}

	for _, c := range cs.constraints {
		satisfied, err := c.check(version, cs.comparer)
		if err != nil {
			return false, err
		}
		if !satisfied {
			return false, nil
		}
	}

	return true, nil
}

// String returns the string representation of constraints
func (cs *Constraints) String() string {
	var strs []string
	for _, c := range cs.constraints {
		strs = append(strs, c.String())
	}
	return strings.Join(strs, ", ")
}

// Constraint operator functions

func constraintEqual(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result == 0, nil
}

func constraintNotEqual(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result != 0, nil
}

func constraintGreaterThan(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

func constraintLessThan(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result < 0, nil
}

func constraintGreaterThanEqual(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result >= 0, nil
}

func constraintLessThanEqual(v, c string, comparer Comparer) (bool, error) {
	result, err := comparer.Compare(v, c)
	if err != nil {
		return false, err
	}
	return result <= 0, nil
}
