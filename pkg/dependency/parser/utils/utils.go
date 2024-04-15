package utils

import (
	"fmt"
	"sort"

	"golang.org/x/exp/maps"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func UniqueStrings(ss []string) []string {
	var results []string
	uniq := make(map[string]struct{})
	for _, s := range ss {
		if _, ok := uniq[s]; ok {
			continue
		}
		results = append(results, s)
		uniq[s] = struct{}{}
	}
	return results
}

func UniqueLibraries(libs []types.Library) []types.Library {
	if len(libs) == 0 {
		return nil
	}
	unique := make(map[string]types.Library)
	for _, lib := range libs {
		identifier := fmt.Sprintf("%s@%s", lib.Name, lib.Version)
		if l, ok := unique[identifier]; !ok {
			unique[identifier] = lib
		} else {
			// There are times when we get 2 same libraries as root and dev dependencies.
			// https://github.com/aquasecurity/trivy/issues/5532
			// In these cases, we need to mark the dependency as a root dependency.
			if !lib.Dev {
				l.Dev = lib.Dev
				unique[identifier] = l
			}

			if len(lib.Locations) > 0 {
				// merge locations
				l.Locations = append(l.Locations, lib.Locations...)
				sort.Sort(l.Locations)
				unique[identifier] = l
			}
		}
	}
	libSlice := maps.Values(unique)
	sort.Sort(types.Libraries(libSlice))

	return libSlice
}

func MergeMaps(parent, child map[string]string) map[string]string {
	if parent == nil {
		return child
	}
	// Clone parent map to avoid shadow overwrite
	newParent := maps.Clone(parent)
	for k, v := range child {
		newParent[k] = v
	}
	return newParent
}
