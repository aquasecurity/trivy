package utils

import (
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"golang.org/x/exp/maps"
)

func FindAncestor(pkgID string, parentMap map[string]ftypes.Packages, seen map[string]struct{}) []string {
	ancestors := map[string]struct{}{}
	seen[pkgID] = struct{}{}
	for _, parent := range parentMap[pkgID] {
		if _, ok := seen[parent.ID]; ok {
			continue
		}
		if !parent.Indirect {
			ancestors[parent.ID] = struct{}{}
		} else if len(parentMap[parent.ID]) == 0 {
			// Direct dependencies cannot be identified in some package managers like "package-lock.json" v1,
			// then the "Indirect" field can be always true. We try to guess direct dependencies in this case.
			// A dependency with no parents must be a direct dependency.
			//
			// e.g.
			//   -> styled-components
			//     -> fbjs
			//       -> isomorphic-fetch
			//         -> node-fetch
			//
			// Even if `styled-components` is not marked as a direct dependency, it must be a direct dependency
			// as it has no parents. Note that it doesn't mean `fbjs` is an indirect dependency.
			ancestors[parent.ID] = struct{}{}
		} else {
			for _, a := range FindAncestor(parent.ID, parentMap, seen) {
				ancestors[a] = struct{}{}
			}
		}
	}
	return maps.Keys(ancestors)
}
