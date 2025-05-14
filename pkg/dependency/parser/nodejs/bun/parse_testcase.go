package bun

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	normalPkgs = []ftypes.Package{
		{
			ID:           "@types/bun@1.2.13",
			Name:         "@types/bun",
			Version:      "1.2.13",
			Relationship: ftypes.RelationshipDirect,
			Locations: ftypes.Locations{
				{
					StartLine: 15,
					EndLine:   15,
				},
			},
		},
		{
			ID:           "typescript@5.8.3",
			Name:         "typescript",
			Version:      "5.8.3",
			Relationship: ftypes.RelationshipDirect,
			Locations: ftypes.Locations{
				{
					StartLine: 21,
					EndLine:   21,
				},
			},
		},
		{
			ID:           "@types/node@22.15.17",
			Name:         "@types/node",
			Version:      "22.15.17",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 17,
					EndLine:   17,
				},
			},
		},
		{
			ID:           "bun-types@1.2.13",
			Name:         "bun-types",
			Version:      "1.2.13",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 19,
					EndLine:   19,
				},
			},
		},
		{
			ID:           "undici-types@6.21.0",
			Name:         "undici-types",
			Version:      "6.21.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 23,
					EndLine:   23,
				},
			},
		},
	}

	normalDeps = []ftypes.Dependency{
		{
			ID:        "@types/bun@1.2.13",
			DependsOn: []string{"bun-types@1.2.13"},
		},
		{
			ID:        "@types/node@22.15.17",
			DependsOn: []string{"undici-types@6.21.0"},
		},
		{
			ID:        "bun-types@1.2.13",
			DependsOn: []string{"@types/node@22.15.17"},
		},
	}
)
