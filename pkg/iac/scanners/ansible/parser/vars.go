package parser

type Vars map[string]any

func mergeVars(parent, child Vars) Vars {
	res := make(Vars)
	for k, v := range parent {
		res[k] = v
	}
	for k, v := range child {
		res[k] = v
	}
	return res
}
