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
			ID:           "my-app@workspace:my-app",
			Name:         "my-app",
			Version:      "workspace:my-app",
			Relationship: ftypes.RelationshipIndirect,
			Locations: ftypes.Locations{
				{
					StartLine: 27,
					EndLine:   27,
				},
			},
		},
		{
			ID:           "my-lib@workspace:my-lib",
			Name:         "my-lib",
			Version:      "workspace:my-lib",
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
			ID:        "@types/node@22.15.17",
			DependsOn: []string{"undici-types@6.21.0"},
		},
		{
			ID:        "bun-types@1.2.13",
			DependsOn: []string{"@types/node@22.15.17"},
		},
	}

	multipleWsDeps = []ftypes.Dependency(nil)
)
