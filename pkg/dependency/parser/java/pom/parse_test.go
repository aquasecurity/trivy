package pom_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/pom"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

var (
	exampleNestedScopeCompile = func(id string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-nested-scope-compile",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleNestedScopeEmpty = func(id string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-nested-scope-empty",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleNestedScopeRuntime = func(id string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-nested-scope-runtime",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleScopeCompile = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-scope-compile",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleScopeEmpty = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-scope-empty",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleScopeRuntime = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-scope-runtime",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}
	exampleApiCompile = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-api-compile",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleApiEmpty = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-api-empty",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleApiRuntime = func(id string) ftypes.Package {
		return ftypes.Package{
			ID:           id,
			Name:         "org.example:example-api-runtime",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}
)

func TestPom_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		local     bool
		offline   bool
		want      []ftypes.Package
		wantDeps  []ftypes.Dependency
		wantErr   string
	}{
		{
			name:      "local repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-runtime",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 37,
							EndLine:   42,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "remote release repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     false,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-runtime",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 37,
							EndLine:   42,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "snapshot dependency",
			inputFile: filepath.Join("testdata", "snapshot", "pom.xml"),
			local:     false,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3-SNAPSHOT",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   18,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "snapshot repository with maven-metadata.xml",
			inputFile: filepath.Join("testdata", "snapshot", "with-maven-metadata", "pom.xml"),
			local:     false,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "2.17.0-SNAPSHOT",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   18,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "offline mode",
			inputFile: filepath.Join("testdata", "offline", "pom.xml"),
			local:     false,
			offline:   true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "org.example:example-offline",
					Version:      "2.3.4",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 17,
							EndLine:   21,
						},
					},
				},
			},
		},
		{
			name:      "inherit parent properties",
			inputFile: filepath.Join("testdata", "parent-properties", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 33,
							EndLine:   37,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "inherit project properties from parent",
			inputFile: filepath.Join("testdata", "project-version-from-parent", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 18,
							EndLine:   22,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "inherit properties in parent depManagement with import scope",
			inputFile: filepath.Join("testdata", "inherit-props", "base", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:test",
					Version:      "0.0.1-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 18,
							EndLine:   21,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "dependencyManagement prefers child properties",
			inputFile: filepath.Join("testdata", "parent-child-properties", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 22,
							EndLine:   26,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "inherit parent dependencies",
			inputFile: filepath.Join("testdata", "parent-dependencies", "child", "pom.xml"),
			local:     false,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "inherit parent dependencyManagement",
			inputFile: filepath.Join("testdata", "parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 26,
							EndLine:   29,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "transitive parents",
			inputFile: filepath.Join("testdata", "transitive-parents", "base", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:base",
					Version:      "4.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-child",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "parent relativePath",
			inputFile: filepath.Join("testdata", "parent-relative-path", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 26,
							EndLine:   30,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "parent version in property",
			inputFile: filepath.Join("testdata", "parent-version-is-property", "child", "pom.xml"),
			local:     false,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 19,
							EndLine:   22,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "parent in a remote repository",
			inputFile: filepath.Join("testdata", "parent-remote-repository", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "org.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 25,
							EndLine:   29,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			// mvn dependency:tree
			// [INFO] com.example:soft:jar:1.0.0
			// [INFO] +- org.example:example-api:jar:1.7.30:compile
			// [INFO] \- org.example:example-dependency:jar:1.2.3:compile
			// Save DependsOn for each package - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "soft requirement",
			inputFile: filepath.Join("testdata", "soft-requirement", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:soft",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 37,
							EndLine:   41,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			// mvn dependency:tree
			// [INFO] com.example:soft-transitive:jar:1.0.0
			// [INFO] +- org.example:example-dependency:jar:1.2.3:compile
			// [INFO] |  \- org.example:example-api:jar:2.0.0:compile
			// [INFO] \- org.example:example-dependency2:jar:2.3.4:compile
			// Save DependsOn for each package - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "soft requirement with transitive dependencies",
			inputFile: filepath.Join("testdata", "soft-requirement-with-transitive-dependencies", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:soft-transitive",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 13,
							EndLine:   17,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency2",
					Version:      "2.3.4",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 18,
							EndLine:   22,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			// mvn dependency:tree
			//[INFO] com.example:hard:jar:1.0.0
			//[INFO] +- org.example:example-nested:jar:3.3.4:compile
			//[INFO] \- org.example:example-dependency:jar:1.2.3:compile
			//[INFO]    \- org.example:example-api:jar:2.0.0:compile
			// Save DependsOn for each package - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "hard requirement for the specified version",
			inputFile: filepath.Join("testdata", "hard-requirement", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 33,
							EndLine:   37,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-nested",
					Version:      "3.3.4",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000005",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
			},
		},
		{
			name:      "version requirement",
			inputFile: filepath.Join("testdata", "version-requirement", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "import dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 34,
							EndLine:   37,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "import multiple dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management-multiple", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 42,
							EndLine:   45,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "exclusions",
			inputFile: filepath.Join("testdata", "exclusions", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:exclusions",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   28,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "exclusions in child",
			inputFile: filepath.Join("testdata", "exclusions-in-child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:example",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-exclusions",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 10,
							EndLine:   14,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		// ➜ mvn dependency:tree
		// ...
		// [INFO]
		// [INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ child ---
		// [INFO] com.example:child:jar:3.0.0
		// [INFO] \- org.example:example-exclusions:jar:3.0.0:compile
		// [INFO]    \- org.example:example-nested:jar:3.3.3:compile
		// [INFO] ------------------------------------------------------------------------
		{
			name:      "exclusions in child and parent dependency management",
			inputFile: filepath.Join("testdata", "exclusions-parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-exclusions",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 26,
							EndLine:   35,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		{
			name:      "exclusions with wildcards",
			inputFile: filepath.Join("testdata", "wildcard-exclusions", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:wildcard-exclusions",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   24,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency2",
					Version:      "2.3.4",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 25,
							EndLine:   35,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 36,
							EndLine:   46,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "multi module",
			inputFile: filepath.Join("testdata", "multi-module", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "com.example:module",
					Version:      "1.1.1",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			// `mvn` doesn't include modules in dep tree of root pom and builds separate graphs.
			// But we have `root` and `workspace` relationships, so we can merge these graphs.
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "multi module with deps with same GAV",
			inputFile: filepath.Join("testdata", "multiple-modules-with-deps-with-same-gav", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000005",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			//[INFO] --------------------------------[ pom ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ module1 ---
			//[INFO] com.example:module1:pom:1.0.0
			//[INFO] \- org.example:example-api:jar:1.7.30:compile
			//[INFO] --------------------------------[ pom ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ module2 ---
			//[INFO] com.example:module2:pom:2.0.0
			//[INFO] \- org.example:example-api:jar:1.7.30:compile
			//[INFO]
			//[INFO] --------------------------------[ pom ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ root ---
			//[INFO] com.example:root:pom:1.0.0
			//[INFO] ------------------------------------------------------------------------
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
			},
		},
		{
			name:      "nested modules",
			inputFile: filepath.Join("testdata", "nested-modules", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:      "3ff14136-e09f-4df9-80ea-000000000004",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					Licenses: []string{
						"The Apache Software License, Version 2.0",
					},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "Infinity loop for modules",
			inputFile: filepath.Join("testdata", "modules-infinity-loop", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "org.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				// as module
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:module-2",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				// as dependency
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "multi module soft requirement",
			inputFile: filepath.Join("testdata", "multi-module-soft-requirement", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "com.example:module1",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "com.example:module2",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000005",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
			},
		},
		{
			name:      "overwrite artifact version from dependencyManagement in the root POM",
			inputFile: filepath.Join("testdata", "root-pom-dep-management", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root-pom-dep-management",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 20,
							EndLine:   24,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "transitive dependencyManagement should not be inherited",
			inputFile: filepath.Join("testdata", "transitive-dependency-management", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "org.example:transitive-dependency-management",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency-management3",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   18,
						},
					},
				},
				// Managed dependencies (org.example:example-api:1.7.30) in org.example:example-dependency-management3
				// should not affect dependencies of example-dependency (org.example:example-api:2.0.0)
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		{
			name:      "parent not found",
			inputFile: filepath.Join("testdata", "not-found-parent", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:no-parent",
					Version:      "1.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 27,
							EndLine:   31,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "dependency not found",
			inputFile: filepath.Join("testdata", "not-found-dependency", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:not-found-dependency",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-not-found",
					Version:      "999",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 21,
							EndLine:   25,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		{
			name:      "module not found - unable to parse module",
			inputFile: filepath.Join("testdata", "not-found-module", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
			},
		},
		{
			name:      "multiply licenses",
			inputFile: filepath.Join("testdata", "multiply-licenses", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:      "3ff14136-e09f-4df9-80ea-000000000001",
					Name:    "com.example:multiply-licenses",
					Version: "1.0.0",
					Licenses: []string{
						"MIT",
						"Apache 2.0",
					},
					Relationship: ftypes.RelationshipRoot,
				},
			},
		},
		{
			name:      "inherit parent license",
			inputFile: filepath.Join("testdata", "inherit-license", "module", "submodule", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example.app:submodule",
					Version:      "1.0.0",
					Licenses:     []string{"Apache-2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
			},
		},
		{
			name:      "compare ArtifactIDs for base and parent pom's",
			inputFile: filepath.Join("testdata", "no-parent-infinity-loop", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
			},
		},
		{
			name:      "dependency without version",
			inputFile: filepath.Join("testdata", "dep-without-version", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:dep-without-version",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 19,
							EndLine:   22,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
			},
		},
		// [INFO] com.example:root-depManagement-in-parent:jar:1.0.0
		// [INFO] \- org.example:example-dependency:jar:2.0.0:compile
		// [INFO]    \- org.example:example-api:jar:1.0.1:compile
		{
			name:      "dependency from parent uses version from root pom depManagement",
			inputFile: filepath.Join("testdata", "use-root-dep-management-in-parent", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 25,
							EndLine:   29,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		// [INFO] com.example:root-depManagement-in-parent:jar:1.0.0
		// [INFO] \- org.example:example-dependency:jar:2.0.0:compile
		// [INFO]    \- org.example:example-api:jar:2.0.1:compile
		{
			name:      "dependency from parent uses version from child pom depManagement",
			inputFile: filepath.Join("testdata", "use-dep-management-from-child-in-parent", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-dependency",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 15,
							EndLine:   19,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api",
					Version:      "2.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
			},
		},
		// [INFO] com.example:child-depManagement-in-parent:jar:1.0.0
		// [INFO] +- org.example:example-api2:jar:1.0.2:runtime
		// [INFO] +- org.example:example-api3:jar:4.0.3:compile
		// [INFO] \- org.example:example-api:jar:1.0.1:compile
		{
			name:      "dependency from parent uses version from child(scanned) pom depManagement",
			inputFile: filepath.Join("testdata", "use-child-dep-management-in-parent", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:child-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-api2",
					Version:      "1.0.2",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-api3",
					Version:      "4.0.3",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
		// [INFO] com.example:inherit-scopes-from-child-deps-and-their-parents:jar:0.0.1
		// [INFO] +- org.example:example-nested-scope-runtime:jar:1.0.0:runtime
		// [INFO] |  \- org.example:example-scope-runtime:jar:2.0.0:runtime
		// [INFO] |     \- org.example:example-api-runtime:jar:3.0.0:runtime
		// [INFO] +- org.example:example-nested-scope-compile:jar:1.0.0:compile
		// [INFO] |  \- org.example:example-scope-compile:jar:2.0.0:compile
		// [INFO] |     \- org.example:example-api-compile:jar:3.0.0:compile
		// [INFO] \- org.example:example-nested-scope-empty:jar:1.0.0:compile
		// [INFO]    \- org.example:example-scope-empty:jar:2.0.0:compile
		// [INFO]       \- org.example:example-api-empty:jar:3.0.0:compile
		//
		// `example-nested-*" dependencies and their parents contain `dependencyManagement` with changed scopes
		{
			name:      "inherit scopes from child dependencies and their parents",
			inputFile: filepath.Join("testdata", "inherit-scopes-from-child-deps-and-their-parents", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:inherit-scopes-from-child-deps-and-their-parents",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("3ff14136-e09f-4df9-80ea-000000000003", 16, 21),
				exampleNestedScopeEmpty("3ff14136-e09f-4df9-80ea-000000000004", 22, 26),
				exampleNestedScopeRuntime("3ff14136-e09f-4df9-80ea-000000000002", 10, 15),
				exampleApiCompile("3ff14136-e09f-4df9-80ea-000000000009"),
				exampleApiEmpty("3ff14136-e09f-4df9-80ea-000000000010"),
				exampleApiRuntime("3ff14136-e09f-4df9-80ea-000000000008"),
				exampleScopeCompile("3ff14136-e09f-4df9-80ea-000000000006"),
				exampleScopeEmpty("3ff14136-e09f-4df9-80ea-000000000007"),
				exampleScopeRuntime("3ff14136-e09f-4df9-80ea-000000000005"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000006",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000007",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000005",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000008",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000006",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000009",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000007",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000010",
					},
				},
			},
		},
		// [INFO] com.example:inherit-scopes-in-parents-from-root:jar:0.1.0
		// [INFO] +- org.example:example-nested-scope-runtime:jar:1.0.0:runtime
		// [INFO] |  \- org.example:example-scope-runtime:jar:2.0.0:compile
		// [INFO] |     \- org.example:example-api-runtime:jar:3.0.0:runtime
		// [INFO] +- org.example:example-nested-scope-compile:jar:1.0.0:compile
		// [INFO] |  \- org.example:example-scope-compile:jar:2.0.0:runtime
		// [INFO] |     \- org.example:example-api-compile:jar:3.0.0:test
		// [INFO] \- org.example:example-nested-scope-empty:jar:1.0.0:compile
		// [INFO]    \- org.example:example-scope-empty:jar:2.0.0:runtime
		// [INFO]       \- org.example:example-api-empty:jar:3.0.0:test
		//
		// `example-nested-*" dependencies and their parents contain `dependencyManagement` with changed scopes
		// scopes from `dependencyManagement` of root pom are used
		{
			name:      "inherit scopes in children from root pom",
			inputFile: filepath.Join("testdata", "inherit-scopes-in-children-from-root", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:inherit-scopes-in-children-from-root",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("3ff14136-e09f-4df9-80ea-000000000003", 51, 56),
				exampleNestedScopeEmpty("3ff14136-e09f-4df9-80ea-000000000004", 57, 61),
				exampleNestedScopeRuntime("3ff14136-e09f-4df9-80ea-000000000002", 45, 50),
				exampleApiRuntime("3ff14136-e09f-4df9-80ea-000000000008"),
				exampleScopeCompile("3ff14136-e09f-4df9-80ea-000000000006"),
				exampleScopeEmpty("3ff14136-e09f-4df9-80ea-000000000007"),
				exampleScopeRuntime("3ff14136-e09f-4df9-80ea-000000000005"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000006",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000007",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000005",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000008",
					},
				},
			},
		},
		// [INFO] com.example:inherit-scopes-in-parents-from-root:jar:0.1.0
		// [INFO] +- org.example:example-nested-scope-runtime:jar:1.0.0:runtime
		// [INFO] |  \- org.example:example-scope-runtime:jar:2.0.0:compile
		// [INFO] |     \- org.example:example-api-runtime:jar:3.0.0:runtime
		// [INFO] +- org.example:example-nested-scope-compile:jar:1.0.0:compile
		// [INFO] |  \- org.example:example-scope-compile:jar:2.0.0:runtime
		// [INFO] |     \- org.example:example-api-compile:jar:3.0.0:test
		// [INFO] \- org.example:example-nested-scope-empty:jar:1.0.0:test
		// [INFO]    \- org.example:example-scope-empty:jar:2.0.0:test
		// [INFO]       \- org.example:example-api-empty:jar:3.0.0:test
		//
		// `example-nested-*" dependencies and their parents contain `dependencyManagement` with changed scopes
		// scopes from `dependencyManagement` of root pom are used in parent dependencies
		{
			name:      "inherit scopes in parent from root pom",
			inputFile: filepath.Join("testdata", "inherit-scopes-in-parents-from-root", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:inherit-scopes-in-parents-from-root",
					Version:      "0.1.0",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("3ff14136-e09f-4df9-80ea-000000000003", 0, 0),
				exampleNestedScopeRuntime("3ff14136-e09f-4df9-80ea-000000000002", 0, 0),
				exampleApiRuntime("3ff14136-e09f-4df9-80ea-000000000006"),
				exampleScopeCompile("3ff14136-e09f-4df9-80ea-000000000005"),
				exampleScopeRuntime("3ff14136-e09f-4df9-80ea-000000000004"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000004",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000006",
					},
				},
			},
		},
		//[INFO] com.example:root-pom-with-spaces:jar:1.0.0
		//[INFO] \- org.example:example-nested:jar:3.3.3:compile
		//[INFO]    \- org.example:example-dependency:jar:1.2.4:compile
		//[INFO]       \- org.example:example-api:jar:2.0.0:compile
		{
			name:      "space at the start and/or end of the text nodes",
			inputFile: filepath.Join("testdata", "with-spaces", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000001",
					Name:         "com.example:root-pom-with-spaces",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000002",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 24,
							EndLine:   28,
						},
					},
				},
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000004",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-with-spaces` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "3ff14136-e09f-4df9-80ea-000000000003",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000001",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000002",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000002",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000003",
					},
				},
				{
					ID: "3ff14136-e09f-4df9-80ea-000000000003",
					DependsOn: []string{
						"3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var remoteRepos []string
			if tt.local {
				// for local repository
				t.Setenv("MAVEN_HOME", "testdata/settings/global")
			} else {
				// for remote repository
				h := http.FileServer(http.Dir(filepath.Join("testdata", "repository")))
				ts := httptest.NewServer(h)
				remoteRepos = []string{ts.URL}
			}

			p := pom.NewParser(tt.inputFile, pom.WithReleaseRemoteRepos(remoteRepos), pom.WithSnapshotRemoteRepos(remoteRepos), pom.WithOffline(tt.offline))

			gotPkgs, gotDeps, err := p.Parse(f)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
