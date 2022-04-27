package strings

import (
	"sort"
	"strconv"
)

func Unique(strings []string) []string {
	sort.Strings(strings)

	var ret []string
	preStr := ""
	for _, s := range strings {
		if preStr != s {
			ret = append(ret, s)
		}
		preStr = s
	}

	return ret
}

func IsInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func InSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func Merge(a, b []string) []string {
	uniq := map[string]struct{}{}
	for _, v := range append(a, b...) {
		uniq[v] = struct{}{}
	}

	var merged []string
	for u := range uniq {
		merged = append(merged, u)
	}
	return merged
}
