package vars

import (
	"maps"

	"github.com/samber/lo"
)

// Vars represents a set of variables as a map from string keys to arbitrary values.
type Vars map[string]any

// Clone creates a shallow copy of Vars.
func (v Vars) Clone() Vars {
	if v == nil {
		return nil
	}
	c := make(Vars, len(v))
	maps.Copy(c, v)
	return c
}

func MergeVars(variables ...Vars) Vars {
	return lo.Assign(variables...)
}
