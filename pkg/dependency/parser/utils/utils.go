package utils

import (
	"fmt"
	"maps"
	"sort"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func UniquePackages(pkgs []ftypes.Package) []ftypes.Package {
	if len(pkgs) == 0 {
		return nil
	}
	unique := make(map[string]ftypes.Package)
	for _, pkg := range pkgs {
		identifier := fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		if l, ok := unique[identifier]; !ok {
			unique[identifier] = pkg
		} else {
			// There are times when we get 2 same packages as root and dev dependencies.
			// https://github.com/aquasecurity/trivy/issues/5532
			// In these cases, we need to mark the dependency as a root dependency.
			if !pkg.Dev {
				l.Dev = pkg.Dev
				unique[identifier] = l
			}

			if len(pkg.Locations) > 0 {
				// merge locations
				l.Locations = append(l.Locations, pkg.Locations...)
				sort.Sort(l.Locations)
				unique[identifier] = l
			}
		}
	}
	pkgSlice := lo.Values(unique)
	sort.Sort(ftypes.Packages(pkgSlice))

	return pkgSlice
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
