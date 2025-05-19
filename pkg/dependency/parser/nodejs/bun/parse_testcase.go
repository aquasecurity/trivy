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
			Dev:          true,
			Locations: ftypes.Locations{
				{
					StartLine: 18,
					EndLine:   18,
				},
			},
		},
		{
			ID:           "typescript@5.8.3",
			Name:         "typescript",
			Version:      "5.8.3",
			Relationship: ftypes.RelationshipDirect,
			Dev:          false,
			Locations: ftypes.Locations{
				{
					StartLine: 24,
					EndLine:   24,
				},
			},
		},
		{
			ID:           "zod@3.24.4",
			Name:         "zod",
			Version:      "3.24.4",
			Relationship: ftypes.RelationshipDirect,
			Dev:          false,
			Locations: ftypes.Locations{
				{
					StartLine: 28,
					EndLine:   28,
				},
			},
		},
		{
			ID:           "@types/node@22.15.18",
			Name:         "@types/node",
			Version:      "22.15.18",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Locations: ftypes.Locations{
				{
					StartLine: 20,
					EndLine:   20,
				},
			},
		},
		{
			ID:           "bun-types@1.2.13",
			Name:         "bun-types",
			Version:      "1.2.13",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          true,
			Locations: ftypes.Locations{
				{
					StartLine: 22,
					EndLine:   22,
				},
			},
		},
		{
			ID:           "undici-types@6.21.0",
			Name:         "undici-types",
			Version:      "6.21.0",
			Relationship: ftypes.RelationshipIndirect,
			Dev:          false,
			Locations: ftypes.Locations{
				{
					StartLine: 26,
					EndLine:   26,
				},
			},
		},
	}

	multipleWsPkgs = []ftypes.Package{
		{
			ID:           "chalk@5.0.1",
			Name:         "chalk",
			Version:      "5.0.1",
			Relationship: ftypes.RelationshipDirect,
			Locations: ftypes.Locations{
				{
					StartLine: 23,
					EndLine:   23,
				},
			},
		},
		{
			ID:           "lodash@4.17.21",
			Name:         "lodash",
			Version:      "4.17.21",
			Relationship: ftypes.RelationshipDirect,
			Locations: ftypes.Locations{
				{
					StartLine: 25,
					EndLine:   25,
				},
			},
		},
		{
			ID:           "my-app@1.0.0",
			Name:         "my-app",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 27,
					EndLine:   27,
				},
			},
		},
		{
			ID:           "my-lib@1.0.0",
			Name:         "my-lib",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 29,
					EndLine:   29,
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
			ID:        "@types/node@22.15.18",
			DependsOn: []string{"undici-types@6.21.0"},
		},
		{
			ID:        "bun-types@1.2.13",
			DependsOn: []string{"@types/node@22.15.18"},
		},
	}

	multipleWsDeps = []ftypes.Dependency(nil)
)
