package utils

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/exp/maps"
)

func UniqueStrings(ss []string) []string {
	var results []string
	uniq := map[string]struct{}{}
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
	unique := map[string]types.Library{}
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

func PackageID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}
