package bun

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	normalPkgs = []ftypes.Package{
		{
			ID:           "typescript@5.8.3",
			Name:         "typescript",
			Version:      "5.8.3",
			Relationship: ftypes.RelationshipDirect,
		},
        {
			ID:           "bun-types@1.2.12",
			Name:         "bun-types",
			Version:      "1.2.12",
			Relationship: ftypes.RelationshipIndirect,
		},
		{
			ID:           "undici-types@6.21.0",
			Name:         "undici-types",
			Version:      "6.21.0",
			Relationship: ftypes.RelationshipIndirect,
		},
	}

	normalDeps = []ftypes.Dependency(nil)
)
