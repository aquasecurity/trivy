package vars

import (
	"github.com/samber/lo"
)

// Vars represents a set of variables as a map from string keys to arbitrary values.
type Vars map[string]any

func MergeVars(parent, child Vars) Vars {
	return lo.Assign(parent, child)
}
