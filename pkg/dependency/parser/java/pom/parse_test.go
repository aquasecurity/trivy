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
		name                      string
		inputFile                 string
		local                     bool
		enableRepoForSettingsRepo bool // use another repo for repository from settings.xml
		offline                   bool
		want                      []ftypes.Package
		wantDeps                  []ftypes.Dependency
		wantErr                   string
	}{
		{
			name:      "local repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "a302c02128623189",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "e71631e7a364f6bf",
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
					ID:           "a3bf26301f7f7318",
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
					ID: "a302c02128623189", // com.example:happy:1.0.0
					DependsOn: []string{
						"a3bf26301f7f7318", // org.example:example-runtime:1.0.0
						"e71631e7a364f6bf", // org.example:example-api:1.7.30
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
					ID:           "a302c02128623189",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "e71631e7a364f6bf",
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
					ID:           "a3bf26301f7f7318",
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
					ID: "a302c02128623189", // com.example:happy:1.0.0
					DependsOn: []string{
						"a3bf26301f7f7318", // org.example:example-runtime:1.0.0
						"e71631e7a364f6bf", // org.example:example-api:1.7.30
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
					ID:           "8ccc0defff5935f9",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "1f825e0f43f57c1f",
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
					ID:           "23653338191185f6",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "1f825e0f43f57c1f", // org.example:example-dependency:1.2.3-SNAPSHOT
					DependsOn: []string{
						"23653338191185f6", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "8ccc0defff5935f9", // com.example:happy:1.0.0
					DependsOn: []string{
						"1f825e0f43f57c1f", // org.example:example-dependency:1.2.3-SNAPSHOT
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
					ID:           "58fa9f0a132dc08d",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "c991922afccef495",
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
					ID:           "d5950bfc868e465e",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "58fa9f0a132dc08d", // com.example:happy:1.0.0
					DependsOn: []string{
						"c991922afccef495", // org.example:example-dependency:2.17.0-SNAPSHOT
					},
				},
				{
					ID: "c991922afccef495", // org.example:example-dependency:2.17.0-SNAPSHOT
					DependsOn: []string{
						"d5950bfc868e465e", // org.example:example-api:2.0.0
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
					ID:           "7cc75b41fb2da4a9",
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
			name:                      "multiple repositories are used",
			inputFile:                 filepath.Join("testdata", "happy", "pom.xml"),
			local:                     false,
			enableRepoForSettingsRepo: true,
			want: []ftypes.Package{
				{
					ID:           "a302c02128623189",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "e71631e7a364f6bf",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"Custom License from custom repo"},
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:           "a3bf26301f7f7318",
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
					ID: "a302c02128623189", // com.example:happy:1.0.0
					DependsOn: []string{
						"a3bf26301f7f7318", // org.example:example-runtime:1.0.0
						"e71631e7a364f6bf", // org.example:example-api:1.7.30
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
					ID:           "f99913faab851ee",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "c5884361c0005408",
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
					ID: "f99913faab851ee",
					DependsOn: []string{
						"c5884361c0005408", // org.example:example-api:1.7.30
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
					ID:           "597860b7df6c4ff1",
					Name:         "com.example:child",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "9ca5a4d0ad1b5614",
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
					ID: "597860b7df6c4ff1", // com.example:child:2.0.0
					DependsOn: []string{
						"9ca5a4d0ad1b5614", // org.example:example-api:2.0.0
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
					ID:           "30035f73a89371ae",
					Name:         "com.example:test",
					Version:      "0.0.1-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "ce31c86605c4985a",
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
					ID: "30035f73a89371ae", // com.example:test:0.0.1-SNAPSHOT
					DependsOn: []string{
						"ce31c86605c4985a", // org.example:example-api:2.0.0
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
					ID:           "b6c336a673c2469c",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "60fa76253c20b088",
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
					ID:           "221fee5d6a9669ba",
					Name:         "org.example:example-api",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "60fa76253c20b088", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"221fee5d6a9669ba", // org.example:example-api:4.0.0
					},
				},
				{
					ID: "b6c336a673c2469c", // com.example:child:1.0.0
					DependsOn: []string{
						"60fa76253c20b088", // org.example:example-dependency:1.2.3
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
					ID:           "cdc3ce213d4c89ba",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "2f579104d036492a",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "cdc3ce213d4c89ba", // com.example:child:1.0.0-SNAPSHOT
					DependsOn: []string{
						"2f579104d036492a", // org.example:example-api:1.7.30
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
					ID:           "69b8f32870d434ab",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "d2229a7d1091c349",
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
					ID: "69b8f32870d434ab", // com.example:child:3.0.0
					DependsOn: []string{
						"d2229a7d1091c349", // org.example:example-api:1.7.30
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
					ID:           "c68788aaab65ce90",
					Name:         "com.example:base",
					Version:      "4.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3bffdbee3586e742",
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
					ID:           "a68e95739d812267",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3bffdbee3586e742", // org.example:example-child:2.0.0
					DependsOn: []string{
						"a68e95739d812267", // org.example:example-api:1.7.30
					},
				},
				{
					ID: "c68788aaab65ce90", // com.example:base:4.0.0
					DependsOn: []string{
						"3bffdbee3586e742", // org.example:example-child:2.0.0
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
					ID:           "42ad18116c22a280",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "d5f0ae9bc4c185b2",
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
					ID: "42ad18116c22a280", // com.example:child:1.0.0
					DependsOn: []string{
						"d5f0ae9bc4c185b2", // org.example:example-api:1.7.30
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
					ID:           "d1a547b0b1fe815",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "a9f8fc7e5a94bd35",
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
					ID: "d1a547b0b1fe815",
					DependsOn: []string{
						"a9f8fc7e5a94bd35", // org.example:example-api:1.1.1
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
					ID:           "fad89fc9d92ee1df",
					Name:         "org.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "d7e76bddecf820ba",
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
					ID: "fad89fc9d92ee1df", // org.example:child:1.0.0
					DependsOn: []string{
						"d7e76bddecf820ba", // org.example:example-api:1.7.30
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
					ID:           "8d42a73a9b3d763f",
					Name:         "com.example:soft",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "2f38d7a0beefe7a9",
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
					ID:           "3c6b5344805dc137",
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
					ID: "3c6b5344805dc137", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"2f38d7a0beefe7a9", // org.example:example-api:1.7.30
					},
				},
				{
					ID: "8d42a73a9b3d763f", // com.example:soft:1.0.0
					DependsOn: []string{
						"2f38d7a0beefe7a9", // org.example:example-api:1.7.30
						"3c6b5344805dc137", // org.example:example-dependency:1.2.3
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
					ID:           "c0e1772aafb3277e",
					Name:         "com.example:soft-transitive",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "3ce2f1f423261371",
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
					ID:           "db8652acfbf70b92",
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
					ID:           "497435d5d2cf648a",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3ce2f1f423261371", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"497435d5d2cf648a", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "c0e1772aafb3277e", // com.example:soft-transitive:1.0.0
					DependsOn: []string{
						"3ce2f1f423261371", // org.example:example-dependency:1.2.3
						"db8652acfbf70b92", // org.example:example-dependency2:2.3.4
					},
				},
				{
					ID: "db8652acfbf70b92", // org.example:example-dependency2:2.3.4
					DependsOn: []string{
						"497435d5d2cf648a", // org.example:example-api:2.0.0
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
					ID:           "62f5ef2dadedd3c0",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "31ca2fffaeeab368",
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
					ID:           "8f4a4bcfd1d4e64b",
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
					ID:           "de424d158d8deaef",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "31ca2fffaeeab368", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"de424d158d8deaef", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "62f5ef2dadedd3c0", // com.example:hard:1.0.0
					DependsOn: []string{
						"31ca2fffaeeab368", // org.example:example-dependency:1.2.3
						"8f4a4bcfd1d4e64b", // org.example:example-nested:3.3.4
					},
				},
				{
					ID: "8f4a4bcfd1d4e64b", // org.example:example-nested:3.3.4
					DependsOn: []string{
						"31ca2fffaeeab368", // org.example:example-dependency:1.2.3
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
					ID:           "4675cb8d0a299dc4",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "ab862f6b3f85809b",
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
		},
		{
			name:      "import dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "5743dcbc360bc62b",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "6537575e211f6e11",
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
					ID: "5743dcbc360bc62b", // com.example:import:2.0.0
					DependsOn: []string{
						"6537575e211f6e11", // org.example:example-api:1.7.30
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
					ID:           "e3fa6c29fe1e14f6",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "807a5be45edfac58",
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
					ID: "e3fa6c29fe1e14f6", // com.example:import:2.0.0
					DependsOn: []string{
						"807a5be45edfac58", // org.example:example-api:1.7.30
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
					ID:           "5e2d41805c043a28",
					Name:         "com.example:exclusions",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "7d2a59bf22c0477b",
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
					ID:           "fc52d05e208dbae4",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "5e2d41805c043a28", // com.example:exclusions:3.0.0
					DependsOn: []string{
						"7d2a59bf22c0477b", // org.example:example-nested:3.3.3
					},
				},
				{
					ID: "7d2a59bf22c0477b", // org.example:example-nested:3.3.3
					DependsOn: []string{
						"fc52d05e208dbae4", // org.example:example-dependency:1.2.3
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
					ID:           "1d893cfbed47cb7",
					Name:         "com.example:example",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "d9903c57a2f4a0a4",
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
					ID:           "bc3d025d47aa579c",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "5bdfcd45a2a96e82",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "1d893cfbed47cb7", // com.example:example:1.0.0
					DependsOn: []string{
						"d9903c57a2f4a0a4", // org.example:example-exclusions:4.0.0
					},
				},
				{
					ID: "d9903c57a2f4a0a4", // org.example:example-exclusions:4.0.0
					DependsOn: []string{
						"5bdfcd45a2a96e82", // org.example:example-dependency:1.2.3
						"bc3d025d47aa579c", // org.example:example-api:1.7.30
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
					ID:           "f51f7e81b9e99185",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "1e4e34b7abdad775",
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
					ID:           "39880dca05f05d7a",
					Name:         "org.example:example-nested",
					Version:      "3.3.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "1e4e34b7abdad775", // org.example:example-exclusions:3.0.0
					DependsOn: []string{
						"39880dca05f05d7a", // org.example:example-nested:3.3.3
					},
				},
				{
					ID: "f51f7e81b9e99185", // com.example:child:3.0.0
					DependsOn: []string{
						"1e4e34b7abdad775", // org.example:example-exclusions:3.0.0
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
					ID:           "87282928cd3dd6f1",
					Name:         "com.example:wildcard-exclusions",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "4ee336bfe28831e",
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
					ID:           "d33d5afe3e1f634d",
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
					ID:           "8253090a236bd189",
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
					ID: "87282928cd3dd6f1", // com.example:wildcard-exclusions:4.0.0
					DependsOn: []string{
						"4ee336bfe28831e",  // org.example:example-dependency:1.2.3
						"8253090a236bd189", // org.example:example-nested:3.3.3
						"d33d5afe3e1f634d", // org.example:example-dependency2:2.3.4
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
					ID:           "d145d452be4e62bf",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "18a86db6d63098ca",
					Name:         "com.example:module",
					Version:      "1.1.1",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "b1fffe9320241c99",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "8f510d0d6a37c946",
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
					ID: "18a86db6d63098ca", // com.example:module:1.1.1
					DependsOn: []string{
						"b1fffe9320241c99", // org.example:example-dependency:1.2.3
					},
				},
				{
					ID: "b1fffe9320241c99", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"8f510d0d6a37c946", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "d145d452be4e62bf", // com.example:aggregation:1.0.0
					DependsOn: []string{
						"18a86db6d63098ca", // com.example:module:1.1.1
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
					ID:           "436691e638307210",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "b35e0c42967feff7",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3a5eb43412437c7a",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "7a86a0fdfe32fdec",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "a4910de2a6224c79",
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
					ID: "3a5eb43412437c7a", // com.example:module2:2.0.0
					DependsOn: []string{
						"a4910de2a6224c79", // org.example:example-api:1.7.30
					},
				},
				{
					ID: "436691e638307210", // com.example:root:1.0.0
					DependsOn: []string{
						"3a5eb43412437c7a", // com.example:module2:2.0.0
						"b35e0c42967feff7", // com.example:module1:1.0.0
					},
				},
				{
					ID: "b35e0c42967feff7", // com.example:module1:1.0.0
					DependsOn: []string{
						"7a86a0fdfe32fdec", // org.example:example-api:1.7.30
					},
				},
			},
		},
		{
			name:      "multi module with similar deps, but different children",
			inputFile: filepath.Join("testdata", "multiple-modules-with-deps-with-same-gav-with-props", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "81b56f8093df9fc",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "b35e0c42967feff7",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3a5eb43412437c7a",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "2634ddc6b04cc5b4",
					Name:         "org.example:example-dependency",
					Version:      "1.2.5",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "b13d2365abea3a75",
					Name:         "org.example:example-dependency",
					Version:      "1.2.5",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "7a86a0fdfe32fdec",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "a4910de2a6224c79",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			//[INFO] --------------------------------[ jar ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ module1 ---
			//[INFO] com.example:module1:jar:1.0.0
			//[INFO] \- org.example:example-dependency:jar:1.2.5:compile
			//[INFO]    \- org.example:example-api:jar:1.7.30:compile
			//[INFO]
			//[INFO] ------------------------< com.example:module2 >-------------------------
			//[INFO] Building module2 2.0.0                                             [2/3]
			//[INFO]   from module2/pom.xml
			//[INFO] --------------------------------[ jar ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ module2 ---
			//[INFO] com.example:module2:jar:2.0.0
			//[INFO] \- org.example:example-dependency:jar:1.2.5:compile
			//[INFO]    \- org.example:example-api:jar:2.0.0:compile
			//[INFO]
			//[INFO] --------------------------< com.example:root >--------------------------
			//[INFO] Building root 1.0.0                                                [3/3]
			//[INFO]   from pom.xml
			//[INFO] --------------------------------[ pom ]---------------------------------
			//[INFO]
			//[INFO] --- dependency:3.7.0:tree (default-cli) @ root ---
			//[INFO] com.example:root:pom:1.0.0
			//[INFO] ------------------------------------------------------------------------
			wantDeps: []ftypes.Dependency{
				{
					ID: "2634ddc6b04cc5b4", // org.example:example-dependency:1.2.5
					DependsOn: []string{
						"b80d1889cd7ec6f3", // org.example:example-api:1.7.30
					},
				},
				{
					ID: "3a5eb43412437c7a", // com.example:module2:2.0.0
					DependsOn: []string{
						"b13d2365abea3a75", // org.example:example-dependency:1.2.5
					},
				},
				{
					ID: "81b56f8093df9fc", // com.example:root:1.0.0
					DependsOn: []string{
						"b35e0c42967feff7", // com.example:module1:1.0.0
						"3a5eb43412437c7a", // com.example:module2:2.0.0
					},
				},
				{
					ID: "b13d2365abea3a75", // org.example:example-dependency:1.2.5
					DependsOn: []string{
						"fda861a0a2dc688a", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "b35e0c42967feff7", // com.example:module1:1.0.0
					DependsOn: []string{
						"2634ddc6b04cc5b4", // org.example:example-dependency:1.2.5
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
					ID:           "1b704e264fae243d",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "b35e0c42967feff7",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3a5eb43412437c7a",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:      "a4910de2a6224c79",
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
					ID: "1b704e264fae243d", // com.example:root:1.0.0
					DependsOn: []string{
						"3a5eb43412437c7a", // com.example:module2:2.0.0
						"b35e0c42967feff7", // com.example:module1:1.0.0
					},
				},
				{
					ID: "3a5eb43412437c7a", // com.example:module2:2.0.0
					DependsOn: []string{
						"a4910de2a6224c79", // org.example:example-api:1.7.30
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
					ID:           "9cfee9e6bd8732c0",
					Name:         "org.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				// as module
				{
					ID:           "53a40d6eafef8ae6",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "34f6e112262938af",
					Name:         "org.example:module-2",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				// as dependency
				{
					ID:           "9a55a6e62a33c07d",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "34f6e112262938af", // org.example:module-2:3.0.0
					DependsOn: []string{
						"9a55a6e62a33c07d", // "org.example:module-1"
					},
				},
				{
					ID: "9cfee9e6bd8732c0", // org.example:root:1.0.0
					DependsOn: []string{
						"34f6e112262938af", // org.example:module-2:3.0.0
						"53a40d6eafef8ae6", // "org.example:module-1"

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
					ID:           "d303364d42a6d9b1",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "4a0482df8e9e52c8",
					Name:         "com.example:module1",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "3db8aeb3a315b2f1",
					Name:         "com.example:module2",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "7a86a0fdfe32fdec",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "cff24b98a8d6a608",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3db8aeb3a315b2f1", // com.example:module2:1.1.1
					DependsOn: []string{
						"cff24b98a8d6a608", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "4a0482df8e9e52c8", // com.example:module1:1.1.1
					DependsOn: []string{
						"7a86a0fdfe32fdec", // org.example:example-api:1.7.30
					},
				},
				{
					ID: "d303364d42a6d9b1", // com.example:aggregation:1.0.0
					DependsOn: []string{
						"3db8aeb3a315b2f1", // com.example:module2:1.1.1
						"4a0482df8e9e52c8", // com.example:module1:1.1.1
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
					ID:           "6251a251f6af929e",
					Name:         "com.example:root-pom-dep-management",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "99356a856a85d38c",
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
					ID:           "ba01a9352a26cb78",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "e4bc8e79430f0370",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "6251a251f6af929e", // com.example:root-pom-dep-management:1.0.0
					DependsOn: []string{
						"99356a856a85d38c", // org.example:example-nested:3.3.3
					},
				},
				{
					ID: "99356a856a85d38c", // org.example:example-nested:3.3.3
					DependsOn: []string{
						"e4bc8e79430f0370", // org.example:example-dependency:1.2.4
					},
				},
				{
					ID: "e4bc8e79430f0370", // org.example:example-dependency:1.2.4
					DependsOn: []string{
						"ba01a9352a26cb78", // org.example:example-api:2.0.0
					},
				},
			},
		},
		{
			name:      "overwrite artifact version from dependencyManagement in the root POM when dependency uses `project.*` props",
			inputFile: filepath.Join("testdata", "root-pom-dep-management-for-deps-with-project-props", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "6c22541d1692f112",
					Name:         "com.example:root-pom-dep-management-for-deps-with-project-props",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "6ae4efb45566f453",
					Name:         "org.example:example-dependency",
					Version:      "1.7.30",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 21,
							EndLine:   25,
						},
					},
				},
				{
					ID:           "7043f18cfc7d83ed",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "6ae4efb45566f453", // org.example:example-dependency:1.7.30
					DependsOn: []string{
						"7043f18cfc7d83ed", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "6c22541d1692f112", // com.example:root-pom-dep-management-for-deps-with-project-props:1.0.0
					DependsOn: []string{
						"6ae4efb45566f453", // org.example:example-dependency:1.7.30
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
					ID:           "a4a119765d23c4cc",
					Name:         "org.example:transitive-dependency-management",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "c472e9e4c00eb785",
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
					ID:           "bd947ff8ba57d98b",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "a4863849ff032b98",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "a4863849ff032b98", // org.example:example-dependency:1.2.3
					DependsOn: []string{
						"bd947ff8ba57d98b", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "a4a119765d23c4cc", // org.example:transitive-dependency-management:2.0.0
					DependsOn: []string{
						"c472e9e4c00eb785", // org.example:example-dependency-management3:1.1.1
					},
				},
				{
					ID: "c472e9e4c00eb785", // org.example:example-dependency-management3:1.1.1
					DependsOn: []string{
						"a4863849ff032b98", // org.example:example-dependency:1.2.3
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
					ID:           "32ac50600af2dcf5",
					Name:         "com.example:no-parent",
					Version:      "1.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "d09fe727eeb17392",
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
					ID: "32ac50600af2dcf5", // com.example:no-parent:1.0-SNAPSHOT
					DependsOn: []string{
						"d09fe727eeb17392", // org.example:example-api:1.7.30
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
					ID:           "e52fae70a221620e",
					Name:         "com.example:not-found-dependency",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "af293727bdcee4ce",
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
					ID: "e52fae70a221620e", // com.example:not-found-dependency:1.0.0
					DependsOn: []string{
						"af293727bdcee4ce", // org.example:example-not-found:999
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
					ID:           "f8aa669ded920c10",
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
					ID:      "22612a3aea77acb",
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
					ID:           "3a92b985f863a203",
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
					ID:           "142e8eb661067dcb",
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
					ID:           "e1cb81d9d59e3f6",
					Name:         "com.example:dep-without-version",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "35b5f95d96c57b5",
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
					ID:           "675b263546ec5eea",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "310f08f995dca6f",
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
					ID:           "343ac62818f0adcc",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "310f08f995dca6f", // org.example:example-dependency:2.0.0
					DependsOn: []string{
						"343ac62818f0adcc", // org.example:example-api:1.0.1
					},
				},
				{
					ID: "675b263546ec5eea", // com.example:root-depManagement-in-parent:1.0.0
					DependsOn: []string{
						"310f08f995dca6f", // org.example:example-dependency:2.0.0
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
					ID:           "7d38e0ad8c454a04",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "329a16534cc26e65",
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
					ID:           "187df2acf1263d9f",
					Name:         "org.example:example-api",
					Version:      "2.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "329a16534cc26e65", // org.example:example-dependency:2.0.0
					DependsOn: []string{
						"187df2acf1263d9f", // org.example:example-api:2.0.1
					},
				},
				{
					ID: "7d38e0ad8c454a04", // com.example:root-depManagement-in-parent:1.0.0
					DependsOn: []string{
						"329a16534cc26e65", // org.example:example-dependency:2.0.0
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
					ID:           "e8d7588088a764ae",
					Name:         "com.example:child-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "5e5fc05f450adeea",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "e378c24d9bebe71d",
					Name:         "org.example:example-api2",
					Version:      "1.0.2",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "f92a10e6db0cf34b",
					Name:         "org.example:example-api3",
					Version:      "4.0.3",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "e8d7588088a764ae", // com.example:child-depManagement-in-parent:1.0.0
					DependsOn: []string{
						"5e5fc05f450adeea", // org.example:example-api:1.0.1
						"e378c24d9bebe71d", // org.example:example-api2:1.0.2
						"f92a10e6db0cf34b", // org.example:example-api3:4.0.3
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
					ID:           "29dfa51e106d2b4a",
					Name:         "com.example:inherit-scopes-from-child-deps-and-their-parents",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("c5c1ec8fffba6cd8", 16, 21),
				exampleNestedScopeEmpty("2e0c37ea8840521", 22, 26),
				exampleNestedScopeRuntime("98ee0b260ba335e5", 10, 15),
				exampleApiCompile("d4015fba907fb567"),
				exampleApiEmpty("9575d06c988f30b6"),
				exampleApiRuntime("91cf1740e5fb14a6"),
				exampleScopeCompile("e168f2d0b2770ae9"),
				exampleScopeEmpty("af2c22db4a139c3e"),
				exampleScopeRuntime("acf8ee16b232f3b0"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "29dfa51e106d2b4a", // com.example:inherit-scopes-from-child-deps-and-their-parents:0.0.1
					DependsOn: []string{
						"2e0c37ea8840521",
						"98ee0b260ba335e5", // org.example:example-nested-scope-runtime:1.0.0
						"c5c1ec8fffba6cd8", // org.example:example-nested-scope-compile:1.0.0
					},
				},
				{
					ID: "2e0c37ea8840521",
					DependsOn: []string{
						"af2c22db4a139c3e", // org.example:example-scope-empty:2.0.0
					},
				},
				{
					ID: "98ee0b260ba335e5", // org.example:example-nested-scope-runtime:1.0.0
					DependsOn: []string{
						"acf8ee16b232f3b0", // org.example:example-scope-runtime:2.0.0
					},
				},
				{
					ID: "acf8ee16b232f3b0", // org.example:example-scope-runtime:2.0.0
					DependsOn: []string{
						"91cf1740e5fb14a6", // org.example:example-api-runtime:3.0.0
					},
				},
				{
					ID: "af2c22db4a139c3e", // org.example:example-scope-empty:2.0.0
					DependsOn: []string{
						"9575d06c988f30b6", // org.example:example-api-empty:3.0.0
					},
				},
				{
					ID: "c5c1ec8fffba6cd8", // org.example:example-nested-scope-compile:1.0.0
					DependsOn: []string{
						"e168f2d0b2770ae9", // org.example:example-scope-compile:2.0.0
					},
				},
				{
					ID: "e168f2d0b2770ae9", // org.example:example-scope-compile:2.0.0
					DependsOn: []string{
						"d4015fba907fb567", // org.example:example-api-compile:3.0.0
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
					ID:           "3dbc8566860a6163",
					Name:         "com.example:inherit-scopes-in-children-from-root",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("e66ec05e39dc6d56", 51, 56),
				exampleNestedScopeEmpty("4c11808bdf473a93", 57, 61),
				exampleNestedScopeRuntime("61fda3e9dfc5de47", 45, 50),
				exampleApiRuntime("95f677d85d2fd92c"),
				exampleScopeCompile("1d3ae149e42344a3"),
				exampleScopeEmpty("7e01cb2142d11120"),
				exampleScopeRuntime("aaaa5004318c2b16"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "3dbc8566860a6163", // com.example:inherit-scopes-in-children-from-root:0.0.1
					DependsOn: []string{
						"4c11808bdf473a93", // org.example:example-nested-scope-empty:1.0.0
						"61fda3e9dfc5de47", // org.example:example-nested-scope-runtime:1.0.0
						"e66ec05e39dc6d56", // org.example:example-nested-scope-compile:1.0.0
					},
				},
				{
					ID: "4c11808bdf473a93", // org.example:example-nested-scope-empty:1.0.0
					DependsOn: []string{
						"7e01cb2142d11120", // org.example:example-scope-empty:2.0.0
					},
				},
				{
					ID: "61fda3e9dfc5de47", // org.example:example-nested-scope-runtime:1.0.0
					DependsOn: []string{
						"aaaa5004318c2b16", // org.example:example-scope-runtime:2.0.0
					},
				},
				{
					ID: "aaaa5004318c2b16", // org.example:example-scope-runtime:2.0.0
					DependsOn: []string{
						"95f677d85d2fd92c", // org.example:example-api-runtime:3.0.0
					},
				},
				{
					ID: "e66ec05e39dc6d56", // org.example:example-nested-scope-compile:1.0.0
					DependsOn: []string{
						"1d3ae149e42344a3", // org.example:example-scope-compile:2.0.0
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
					ID:           "ac1ed632be1c34d4",
					Name:         "com.example:inherit-scopes-in-parents-from-root",
					Version:      "0.1.0",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("4ce69e4d77dfb604", 0, 0),
				exampleNestedScopeRuntime("9660d65750827d89", 0, 0),
				exampleApiRuntime("efcdf95e971b25a6"),
				exampleScopeCompile("c30b48fb9ad8989d"),
				exampleScopeRuntime("ea3219cbc4dfbe20"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "4ce69e4d77dfb604", // org.example:example-nested-scope-compile:1.0.0
					DependsOn: []string{
						"c30b48fb9ad8989d", // org.example:example-scope-compile:2.0.0
					},
				},
				{
					ID: "9660d65750827d89", // org.example:example-nested-scope-runtime:1.0.0
					DependsOn: []string{
						"ea3219cbc4dfbe20", // org.example:example-scope-runtime:2.0.0
					},
				},
				{
					ID: "ac1ed632be1c34d4", // com.example:inherit-scopes-in-parents-from-root:0.1.0
					DependsOn: []string{
						"4ce69e4d77dfb604", // org.example:example-nested-scope-compile:1.0.0
						"9660d65750827d89", // org.example:example-nested-scope-runtime:1.0.0
					},
				},
				{
					ID: "ea3219cbc4dfbe20", // org.example:example-scope-runtime:2.0.0
					DependsOn: []string{
						"efcdf95e971b25a6", // org.example:example-api-runtime:3.0.0
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
					ID:           "eae09abeffbd78e5",
					Name:         "com.example:root-pom-with-spaces",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "11f4a96e8c45198a",
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
					ID:           "c993486081afe38e",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-with-spaces` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "13e3505f52cbbcba",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "11f4a96e8c45198a", // org.example:example-nested:3.3.3
					DependsOn: []string{
						"13e3505f52cbbcba", // org.example:example-dependency:1.2.4
					},
				},
				{
					ID: "13e3505f52cbbcba", // org.example:example-dependency:1.2.4
					DependsOn: []string{
						"c993486081afe38e", // org.example:example-api:2.0.0
					},
				},
				{
					ID: "eae09abeffbd78e5", // com.example:root-pom-with-spaces:1.0.0
					DependsOn: []string{
						"11f4a96e8c45198a", // org.example:example-nested:3.3.3
					},
				},
			},
		},
		// `mvn` can take values from multiple dependencyManagement sections (from both the root and parent POMs).
		// However, it does not override the `test` scope defined in the parent POM.
		// [INFO] --- dependency:3.7.0:tree (default-cli) @ get-fields-from-multiple-depmanagements ---
		// [INFO] com.example:get-fields-from-multiple-depmanagements:jar:1.0.0
		// [INFO] \- org.example:example-dependency:jar:4.0.0:compile
		// [INFO]    +- org.example:example-api4:jar:4.0.0:compile
		// [INFO]    +- org.example:example-api5:jar:4.0.0:test
		// [INFO]    \- org.example:example-api6:jar:1.7.30:runtime
		// [INFO] ------------------------------------------------------------------------
		{
			name:      "don't overwrite test scope from upper depManagement",
			inputFile: filepath.Join("testdata", "get-fields-from-multiple-depmanagements", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "6c3b7d0c8217d866",
					Name:         "com.example:get-fields-from-multiple-depmanagements",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "1c05143b57e7400b",
					Name:         "org.example:example-dependency",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 30,
							EndLine:   34,
						},
					},
				},
				{
					ID:           "faae46bbe6a75b69",
					Name:         "org.example:example-api4",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "779e40606af7356e",
					Name:         "org.example:example-api6",
					Version:      "1.7.30",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "1c05143b57e7400b", // org.example:example-dependency:4.0.0
					DependsOn: []string{
						"779e40606af7356e", // org.example:example-api6:1.7.30
						"faae46bbe6a75b69", // org.example:example-api4:4.0.0
					},
				},
				{
					ID: "6c3b7d0c8217d866", // com.example:get-fields-from-multiple-depmanagements:1.0.0
					DependsOn: []string{
						"1c05143b57e7400b", // org.example:example-dependency:4.0.0
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var defaultRepo string
			var settingsRepos []string
			if tt.local {
				// for local repository
				t.Setenv("MAVEN_HOME", "testdata/settings/global")
			} else {
				// for remote repository
				h := http.FileServer(http.Dir(filepath.Join("testdata", "repository")))
				ts := httptest.NewServer(h)
				defaultRepo = ts.URL

				// Enable custom repository to be sure in repository order checking
				if tt.enableRepoForSettingsRepo {
					ch := http.FileServer(http.Dir(filepath.Join("testdata", "repository-for-settings-repo")))
					cts := httptest.NewServer(ch)
					settingsRepos = []string{cts.URL}
				}
			}

			p := pom.NewParser(tt.inputFile, pom.WithDefaultRepo(defaultRepo, true, true),
				pom.WithSettingsRepos(settingsRepos, true, false), pom.WithOffline(tt.offline))

			gotPkgs, gotDeps, err := p.Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
