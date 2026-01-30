package pom_test

import (
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/pom"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	exampleNestedScopeCompile = func(hash string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-nested-scope-compile:1.0.0::%s", hash),
			Name:         "org.example:example-nested-scope-compile",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleNestedScopeEmpty = func(hash string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-nested-scope-empty:1.0.0::%s", hash),
			Name:         "org.example:example-nested-scope-empty",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleNestedScopeRuntime = func(hash string, start, end int) ftypes.Package {
		var location ftypes.Locations
		if start != 0 && end != 0 {
			location = append(location, ftypes.Location{
				StartLine: start,
				EndLine:   end,
			})
		}
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-nested-scope-runtime:1.0.0::%s", hash),
			Name:         "org.example:example-nested-scope-runtime",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipDirect,
			Locations:    location,
		}
	}

	exampleScopeCompile = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-scope-compile:2.0.0::%s", hash),
			Name:         "org.example:example-scope-compile",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleScopeEmpty = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-scope-empty:2.0.0::%s", hash),
			Name:         "org.example:example-scope-empty",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleScopeRuntime = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-scope-runtime:2.0.0::%s", hash),
			Name:         "org.example:example-scope-runtime",
			Version:      "2.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}
	exampleApiCompile = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-api-compile:3.0.0::%s", hash),
			Name:         "org.example:example-api-compile",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleApiEmpty = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-api-empty:3.0.0::%s", hash),
			Name:         "org.example:example-api-empty",
			Version:      "3.0.0",
			Relationship: ftypes.RelationshipIndirect,
		}
	}

	exampleApiRuntime = func(hash string) ftypes.Package {
		return ftypes.Package{
			ID:           fmt.Sprintf("org.example:example-api-runtime:3.0.0::%s", hash),
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
					ID:           "com.example:happy:1.0.0::a302c021",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::e71631e7",
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
					ID:           "org.example:example-runtime:1.0.0::a3bf2630",
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
					ID: "com.example:happy:1.0.0::a302c021",
					DependsOn: []string{
						"org.example:example-api:1.7.30::e71631e7",
						"org.example:example-runtime:1.0.0::a3bf2630",
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
					ID:           "com.example:happy:1.0.0::a302c021",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::e71631e7",
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
					ID:           "org.example:example-runtime:1.0.0::a3bf2630",
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
					ID: "com.example:happy:1.0.0::a302c021",
					DependsOn: []string{
						"org.example:example-api:1.7.30::e71631e7",
						"org.example:example-runtime:1.0.0::a3bf2630",
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
					ID:           "com.example:happy:1.0.0::8ccc0def",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:1.2.3-SNAPSHOT::1f825e0f",
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
					ID:           "org.example:example-api:2.0.0::23653338",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:happy:1.0.0::8ccc0def",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3-SNAPSHOT::1f825e0f",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3-SNAPSHOT::1f825e0f",
					DependsOn: []string{
						"org.example:example-api:2.0.0::23653338",
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
					ID:           "com.example:happy:1.0.0::58fa9f0a",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:2.17.0-SNAPSHOT::c991922a",
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
					ID:           "org.example:example-api:2.0.0::d5950bfc",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:happy:1.0.0::58fa9f0a",
					DependsOn: []string{
						"org.example:example-dependency:2.17.0-SNAPSHOT::c991922a",
					},
				},
				{
					ID: "org.example:example-dependency:2.17.0-SNAPSHOT::c991922a",
					DependsOn: []string{
						"org.example:example-api:2.0.0::d5950bfc",
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
					ID:           "org.example:example-offline:2.3.4::7cc75b41",
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
					ID:           "com.example:happy:1.0.0::a302c021",
					Name:         "com.example:happy",
					Version:      "1.0.0",
					Licenses:     []string{"BSD-3-Clause"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::e71631e7",
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
					ID:           "org.example:example-runtime:1.0.0::a3bf2630",
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
					ID: "com.example:happy:1.0.0::a302c021",
					DependsOn: []string{
						"org.example:example-api:1.7.30::e71631e7",
						"org.example:example-runtime:1.0.0::a3bf2630",
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
					ID:           "com.example:child:1.0.0::f99913fa",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::c5884361",
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
					ID: "com.example:child:1.0.0::f99913fa",
					DependsOn: []string{
						"org.example:example-api:1.7.30::c5884361",
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
					ID:           "com.example:child:2.0.0::597860b7",
					Name:         "com.example:child",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:2.0.0::9ca5a4d0",
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
					ID: "com.example:child:2.0.0::597860b7",
					DependsOn: []string{
						"org.example:example-api:2.0.0::9ca5a4d0",
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
					ID:           "com.example:test:0.0.1-SNAPSHOT::30035f73",
					Name:         "com.example:test",
					Version:      "0.0.1-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:2.0.0::ce31c866",
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
					ID: "com.example:test:0.0.1-SNAPSHOT::30035f73",
					DependsOn: []string{
						"org.example:example-api:2.0.0::ce31c866",
					},
				},
			},
		},
		// [INFO] com.example:child:jar:1.2.3
		// [INFO] +- org.example:example-dependency:jar:1.2.3:compile
		// [INFO] |  \- org.example:example-api:jar:4.0.0:compile
		// [INFO] \- org.example:example-api3:jar:4.0.3:compile
		{
			name:      "dependencyManagement prefers child properties",
			inputFile: filepath.Join("testdata", "parent-child-properties", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "com.example:child:1.2.3::14cce9f5",
					Name:         "com.example:child",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api3:4.0.3::c4062c26",
					Name:         "org.example:example-api3",
					Version:      "4.0.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 30,
							EndLine:   34,
						},
					},
				},
				{
					ID:           "org.example:example-dependency:1.2.3::d1f3e5ff",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: ftypes.Locations{
						{
							StartLine: 25,
							EndLine:   29,
						},
					},
				},
				{
					ID:           "org.example:example-api:4.0.0::daf5884b",
					Name:         "org.example:example-api",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:child:1.2.3::14cce9f5",
					DependsOn: []string{
						"org.example:example-api3:4.0.3::c4062c26",
						"org.example:example-dependency:1.2.3::d1f3e5ff",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::d1f3e5ff",
					DependsOn: []string{
						"org.example:example-api:4.0.0::daf5884b",
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
					ID:           "com.example:child:1.0.0-SNAPSHOT::cdc3ce21",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::2f579104",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:child:1.0.0-SNAPSHOT::cdc3ce21",
					DependsOn: []string{
						"org.example:example-api:1.7.30::2f579104",
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
					ID:           "com.example:child:3.0.0::69b8f328",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::d2229a7d",
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
					ID: "com.example:child:3.0.0::69b8f328",
					DependsOn: []string{
						"org.example:example-api:1.7.30::d2229a7d",
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
					ID:           "com.example:base:4.0.0::c68788aa",
					Name:         "com.example:base",
					Version:      "4.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-child:2.0.0::3bffdbee",
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
					ID:           "org.example:example-api:1.7.30::a68e9573",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:base:4.0.0::c68788aa",
					DependsOn: []string{
						"org.example:example-child:2.0.0::3bffdbee",
					},
				},
				{
					ID: "org.example:example-child:2.0.0::3bffdbee",
					DependsOn: []string{
						"org.example:example-api:1.7.30::a68e9573",
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
					ID:           "com.example:child:1.0.0::42ad1811",
					Name:         "com.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::d5f0ae9b",
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
					ID: "com.example:child:1.0.0::42ad1811",
					DependsOn: []string{
						"org.example:example-api:1.7.30::d5f0ae9b",
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
					ID:           "com.example:child:1.0.0-SNAPSHOT::d1a547b0",
					Name:         "com.example:child",
					Version:      "1.0.0-SNAPSHOT",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.1.1::a9f8fc7e",
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
					ID: "com.example:child:1.0.0-SNAPSHOT::d1a547b0",
					DependsOn: []string{
						"org.example:example-api:1.1.1::a9f8fc7e",
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
					ID:           "org.example:child:1.0.0::fad89fc9",
					Name:         "org.example:child",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::d7e76bdd",
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
					ID: "org.example:child:1.0.0::fad89fc9",
					DependsOn: []string{
						"org.example:example-api:1.7.30::d7e76bdd",
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
					ID:           "com.example:soft:1.0.0::8d42a73a",
					Name:         "com.example:soft",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::2f38d7a0",
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
					ID:           "org.example:example-dependency:1.2.3::3c6b5344",
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
					ID: "com.example:soft:1.0.0::8d42a73a",
					DependsOn: []string{
						"org.example:example-api:1.7.30::2f38d7a0",
						"org.example:example-dependency:1.2.3::3c6b5344",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::3c6b5344",
					DependsOn: []string{
						"org.example:example-api:1.7.30::2f38d7a0",
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
					ID:           "com.example:soft-transitive:1.0.0::c0e1772a",
					Name:         "com.example:soft-transitive",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::3ce2f1f4",
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
					ID:           "org.example:example-dependency2:2.3.4::db8652ac",
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
					ID:           "org.example:example-api:2.0.0::497435d5",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:soft-transitive:1.0.0::c0e1772a",
					DependsOn: []string{
						"org.example:example-dependency2:2.3.4::db8652ac",
						"org.example:example-dependency:1.2.3::3ce2f1f4",
					},
				},
				{
					ID: "org.example:example-dependency2:2.3.4::db8652ac",
					DependsOn: []string{
						"org.example:example-api:2.0.0::497435d5",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::3ce2f1f4",
					DependsOn: []string{
						"org.example:example-api:2.0.0::497435d5",
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
					ID:           "com.example:hard:1.0.0::62f5ef2d",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::31ca2fff",
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
					ID:           "org.example:example-nested:3.3.4::8f4a4bcf",
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
					ID:           "org.example:example-api:2.0.0::de424d15",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:hard:1.0.0::62f5ef2d",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3::31ca2fff",
						"org.example:example-nested:3.3.4::8f4a4bcf",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::31ca2fff",
					DependsOn: []string{
						"org.example:example-api:2.0.0::de424d15",
					},
				},
				{
					ID: "org.example:example-nested:3.3.4::8f4a4bcf",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3::31ca2fff",
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
					ID:           "com.example:hard:1.0.0::4675cb8d",
					Name:         "com.example:hard",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api::ab862f6b",
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
					ID:           "com.example:import:2.0.0::5743dcbc",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::6537575e",
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
					ID: "com.example:import:2.0.0::5743dcbc",
					DependsOn: []string{
						"org.example:example-api:1.7.30::6537575e",
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
					ID:           "com.example:import:2.0.0::e3fa6c29",
					Name:         "com.example:import",
					Version:      "2.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::807a5be4",
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
					ID: "com.example:import:2.0.0::e3fa6c29",
					DependsOn: []string{
						"org.example:example-api:1.7.30::807a5be4",
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
					ID:           "com.example:exclusions:3.0.0::5e2d4180",
					Name:         "com.example:exclusions",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-nested:3.3.3::7d2a59bf",
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
					ID:           "org.example:example-dependency:1.2.3::fc52d05e",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:exclusions:3.0.0::5e2d4180",
					DependsOn: []string{
						"org.example:example-nested:3.3.3::7d2a59bf",
					},
				},
				{
					ID: "org.example:example-nested:3.3.3::7d2a59bf",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3::fc52d05e",
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
					ID:           "com.example:example:1.0.0::1d893cfb",
					Name:         "com.example:example",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-exclusions:4.0.0::d9903c57",
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
					ID:           "org.example:example-api:1.7.30::bc3d025d",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::5bdfcd45",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:example:1.0.0::1d893cfb",
					DependsOn: []string{
						"org.example:example-exclusions:4.0.0::d9903c57",
					},
				},
				{
					ID: "org.example:example-exclusions:4.0.0::d9903c57",
					DependsOn: []string{
						"org.example:example-api:1.7.30::bc3d025d",
						"org.example:example-dependency:1.2.3::5bdfcd45",
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
		// [INFO]    \- org.example:example-nested:jar:3.3.5:compile
		// [INFO] ------------------------------------------------------------------------
		// org.example:example-dependency is excluded via com.example:child (dependencies)
		// org.example:example-dependency2 is excluded via com.example:parent (dependencyManagement)
		// org.example:example-api2 is excluded via org.example:example-exclusions (dependencies)
		// org.example:example-api3 is excluded via com.example:parent (dependencyManagement)
		{
			name:      "exclusions in child and parent dependency management",
			inputFile: filepath.Join("testdata", "exclusions-parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []ftypes.Package{
				{
					ID:           "com.example:child:3.0.0::f51f7e81",
					Name:         "com.example:child",
					Version:      "3.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-exclusions:3.0.0::1e4e34b7",
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
					ID:           "org.example:example-nested:3.3.5::c5a28f33",
					Name:         "org.example:example-nested",
					Version:      "3.3.5",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:child:3.0.0::f51f7e81",
					DependsOn: []string{
						"org.example:example-exclusions:3.0.0::1e4e34b7",
					},
				},
				{
					ID: "org.example:example-exclusions:3.0.0::1e4e34b7",
					DependsOn: []string{
						"org.example:example-nested:3.3.5::c5a28f33",
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
					ID:           "com.example:wildcard-exclusions:4.0.0::87282928",
					Name:         "com.example:wildcard-exclusions",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::4ee336bf",
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
					ID:           "org.example:example-dependency2:2.3.4::d33d5afe",
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
					ID:           "org.example:example-nested:3.3.3::8253090a",
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
					ID: "com.example:wildcard-exclusions:4.0.0::87282928",
					DependsOn: []string{
						"org.example:example-dependency2:2.3.4::d33d5afe",
						"org.example:example-dependency:1.2.3::4ee336bf",
						"org.example:example-nested:3.3.3::8253090a",
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
					ID:           "com.example:aggregation:1.0.0::d145d452",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "com.example:module:1.1.1::822ec30d",
					Name:         "com.example:module",
					Version:      "1.1.1",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::493c9a85",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api:2.0.0::fb4eb559",
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
					ID: "com.example:aggregation:1.0.0::d145d452",
					DependsOn: []string{
						"com.example:module:1.1.1::822ec30d",
					},
				},
				{
					ID: "com.example:module:1.1.1::822ec30d",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3::493c9a85",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::493c9a85",
					DependsOn: []string{
						"org.example:example-api:2.0.0::fb4eb559",
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
					ID:           "com.example:root:1.0.0::436691e6",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "com.example:module1:1.0.0::4c39d72a",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "com.example:module2:2.0.0::57fc775b",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "org.example:example-api:1.7.30::80048fd3",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api:1.7.30::8810f687",
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
					ID: "com.example:module1:1.0.0::4c39d72a",
					DependsOn: []string{
						"org.example:example-api:1.7.30::80048fd3",
					},
				},
				{
					ID: "com.example:module2:2.0.0::57fc775b",
					DependsOn: []string{
						"org.example:example-api:1.7.30::8810f687",
					},
				},
				{
					ID: "com.example:root:1.0.0::436691e6",
					DependsOn: []string{
						"com.example:module1:1.0.0::4c39d72a",
						"com.example:module2:2.0.0::57fc775b",
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
					ID:           "com.example:root:1.0.0::81b56f80",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "com.example:module1:1.0.0::919ee306",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "com.example:module2:2.0.0::e4f6bb04",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "org.example:example-dependency:1.2.5::e2ecf3a4",
					Name:         "org.example:example-dependency",
					Version:      "1.2.5",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-dependency:1.2.5::e3e3d7fe",
					Name:         "org.example:example-dependency",
					Version:      "1.2.5",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api:1.7.30::a4032585",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "org.example:example-api:2.0.0::6c475df9",
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
					ID: "com.example:module1:1.0.0::919ee306",
					DependsOn: []string{
						"org.example:example-dependency:1.2.5::e3e3d7fe",
					},
				},
				{
					ID: "com.example:module2:2.0.0::e4f6bb04",
					DependsOn: []string{
						"org.example:example-dependency:1.2.5::e2ecf3a4",
					},
				},
				{
					ID: "com.example:root:1.0.0::81b56f80",
					DependsOn: []string{
						"com.example:module1:1.0.0::919ee306",
						"com.example:module2:2.0.0::e4f6bb04",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.5::e2ecf3a4",
					DependsOn: []string{
						"org.example:example-api:2.0.0::6c475df9",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.5::e3e3d7fe",
					DependsOn: []string{
						"org.example:example-api:1.7.30::a4032585",
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
					ID:           "com.example:root:1.0.0::1b704e26",
					Name:         "com.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "com.example:module1:1.0.0::59758428",
					Name:         "com.example:module1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "com.example:module2:2.0.0::a36f3d58",
					Name:         "com.example:module2",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:      "org.example:example-api:1.7.30::2946ca63",
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
					ID: "com.example:module2:2.0.0::a36f3d58",
					DependsOn: []string{
						"org.example:example-api:1.7.30::2946ca63",
					},
				},
				{
					ID: "com.example:root:1.0.0::1b704e26",
					DependsOn: []string{
						"com.example:module1:1.0.0::59758428",
						"com.example:module2:2.0.0::a36f3d58",
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
					ID:           "org.example:root:1.0.0::9cfee9e6",
					Name:         "org.example:root",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				// as module
				{
					ID:           "org.example:module-1:2.0.0::f8434436",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "org.example:module-2:3.0.0::70a6381c",
					Name:         "org.example:module-2",
					Version:      "3.0.0",
					Relationship: ftypes.RelationshipWorkspace,
				},
				// as dependency
				{
					ID:           "org.example:module-1:2.0.0::86dd9fb8",
					Name:         "org.example:module-1",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "org.example:module-2:3.0.0::70a6381c",
					DependsOn: []string{
						"org.example:module-1:2.0.0::86dd9fb8",
					},
				},
				{
					ID: "org.example:root:1.0.0::9cfee9e6",
					DependsOn: []string{
						"org.example:module-1:2.0.0::f8434436",
						"org.example:module-2:3.0.0::70a6381c",
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
					ID:           "com.example:aggregation:1.0.0::d303364d",
					Name:         "com.example:aggregation",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "com.example:module1:1.1.1::ede50f46",
					Name:         "com.example:module1",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "com.example:module2:1.1.1::ce791b4f",
					Name:         "com.example:module2",
					Version:      "1.1.1",
					Relationship: ftypes.RelationshipWorkspace,
				},
				{
					ID:           "org.example:example-api:1.7.30::5832af90",
					Name:         "org.example:example-api",
					Version:      "1.7.30",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api:2.0.0::95bb5ac5",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:aggregation:1.0.0::d303364d",
					DependsOn: []string{
						"com.example:module1:1.1.1::ede50f46",
						"com.example:module2:1.1.1::ce791b4f",
					},
				},
				{
					ID: "com.example:module1:1.1.1::ede50f46",
					DependsOn: []string{
						"org.example:example-api:1.7.30::5832af90",
					},
				},
				{
					ID: "com.example:module2:1.1.1::ce791b4f",
					DependsOn: []string{
						"org.example:example-api:2.0.0::95bb5ac5",
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
					ID:           "com.example:root-pom-dep-management:1.0.0::6251a251",
					Name:         "com.example:root-pom-dep-management",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-nested:3.3.3::99356a85",
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
					ID:           "org.example:example-api:2.0.0::ba01a935",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "org.example:example-dependency:1.2.4::e4bc8e79",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:root-pom-dep-management:1.0.0::6251a251",
					DependsOn: []string{
						"org.example:example-nested:3.3.3::99356a85",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.4::e4bc8e79",
					DependsOn: []string{
						"org.example:example-api:2.0.0::ba01a935",
					},
				},
				{
					ID: "org.example:example-nested:3.3.3::99356a85",
					DependsOn: []string{
						"org.example:example-dependency:1.2.4::e4bc8e79",
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
					ID:           "com.example:root-pom-dep-management-for-deps-with-project-props:1.0.0::6c22541d",
					Name:         "com.example:root-pom-dep-management-for-deps-with-project-props",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:1.7.30::6ae4efb4",
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
					ID:           "org.example:example-api:2.0.0::7043f18c",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:root-pom-dep-management-for-deps-with-project-props:1.0.0::6c22541d",
					DependsOn: []string{
						"org.example:example-dependency:1.7.30::6ae4efb4",
					},
				},
				{
					ID: "org.example:example-dependency:1.7.30::6ae4efb4",
					DependsOn: []string{
						"org.example:example-api:2.0.0::7043f18c",
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
					ID:           "org.example:transitive-dependency-management:2.0.0::a4a11976",
					Name:         "org.example:transitive-dependency-management",
					Version:      "2.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency-management3:1.1.1::c472e9e4",
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
					ID:           "org.example:example-api:2.0.0::bd947ff8",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "org.example:example-dependency:1.2.3::a4863849",
					Name:         "org.example:example-dependency",
					Version:      "1.2.3",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "org.example:example-dependency-management3:1.1.1::c472e9e4",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3::a4863849",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3::a4863849",
					DependsOn: []string{
						"org.example:example-api:2.0.0::bd947ff8",
					},
				},
				{
					ID: "org.example:transitive-dependency-management:2.0.0::a4a11976",
					DependsOn: []string{
						"org.example:example-dependency-management3:1.1.1::c472e9e4",
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
					ID:           "com.example:no-parent:1.0-SNAPSHOT::32ac5060",
					Name:         "com.example:no-parent",
					Version:      "1.0-SNAPSHOT",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.7.30::d09fe727",
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
					ID: "com.example:no-parent:1.0-SNAPSHOT::32ac5060",
					DependsOn: []string{
						"org.example:example-api:1.7.30::d09fe727",
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
					ID:           "com.example:not-found-dependency:1.0.0::e52fae70",
					Name:         "com.example:not-found-dependency",
					Version:      "1.0.0",
					Licenses:     []string{"Apache 2.0"},
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-not-found:999::af293727",
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
					ID: "com.example:not-found-dependency:1.0.0::e52fae70",
					DependsOn: []string{
						"org.example:example-not-found:999::af293727",
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
					ID:           "com.example:aggregation:1.0.0::f8aa669d",
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
					ID:      "com.example:multiply-licenses:1.0.0::22612a3a",
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
					ID:           "com.example.app:submodule:1.0.0::3a92b985",
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
					ID:           "com.example:child:1.0.0::142e8eb6",
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
					ID:           "com.example:dep-without-version:1.0.0::e1cb81d9",
					Name:         "com.example:dep-without-version",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api::35b5f95d",
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
					ID:           "com.example:root-depManagement-in-parent:1.0.0::675b2635",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:2.0.0::310f08f9",
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
					ID:           "org.example:example-api:1.0.1::343ac628",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:root-depManagement-in-parent:1.0.0::675b2635",
					DependsOn: []string{
						"org.example:example-dependency:2.0.0::310f08f9",
					},
				},
				{
					ID: "org.example:example-dependency:2.0.0::310f08f9",
					DependsOn: []string{
						"org.example:example-api:1.0.1::343ac628",
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
					ID:           "com.example:root-depManagement-in-parent:1.0.0::7d38e0ad",
					Name:         "com.example:root-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:2.0.0::329a1653",
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
					ID:           "org.example:example-api:2.0.1::187df2ac",
					Name:         "org.example:example-api",
					Version:      "2.0.1",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:root-depManagement-in-parent:1.0.0::7d38e0ad",
					DependsOn: []string{
						"org.example:example-dependency:2.0.0::329a1653",
					},
				},
				{
					ID: "org.example:example-dependency:2.0.0::329a1653",
					DependsOn: []string{
						"org.example:example-api:2.0.1::187df2ac",
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
					ID:           "com.example:child-depManagement-in-parent:1.0.0::e8d75880",
					Name:         "com.example:child-depManagement-in-parent",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-api:1.0.1::5e5fc05f",
					Name:         "org.example:example-api",
					Version:      "1.0.1",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api2:1.0.2::e378c24d",
					Name:         "org.example:example-api2",
					Version:      "1.0.2",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					ID:           "org.example:example-api3:4.0.3::f92a10e6",
					Name:         "org.example:example-api3",
					Version:      "4.0.3",
					Relationship: ftypes.RelationshipDirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:child-depManagement-in-parent:1.0.0::e8d75880",
					DependsOn: []string{
						"org.example:example-api2:1.0.2::e378c24d",
						"org.example:example-api3:4.0.3::f92a10e6",
						"org.example:example-api:1.0.1::5e5fc05f",
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
					ID:           "com.example:inherit-scopes-from-child-deps-and-their-parents:0.0.1::29dfa51e",
					Name:         "com.example:inherit-scopes-from-child-deps-and-their-parents",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("c5c1ec8f", 16, 21),
				exampleNestedScopeEmpty("2e0c37ea", 22, 26),
				exampleNestedScopeRuntime("98ee0b26", 10, 15),
				exampleApiCompile("d4015fba"),
				exampleApiEmpty("9575d06c"),
				exampleApiRuntime("91cf1740"),
				exampleScopeCompile("e168f2d0"),
				exampleScopeEmpty("af2c22db"),
				exampleScopeRuntime("acf8ee16"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:inherit-scopes-from-child-deps-and-their-parents:0.0.1::29dfa51e",
					DependsOn: []string{
						"org.example:example-nested-scope-compile:1.0.0::c5c1ec8f",
						"org.example:example-nested-scope-empty:1.0.0::2e0c37ea",
						"org.example:example-nested-scope-runtime:1.0.0::98ee0b26",
					},
				},
				{
					ID: "org.example:example-nested-scope-compile:1.0.0::c5c1ec8f",
					DependsOn: []string{
						"org.example:example-scope-compile:2.0.0::e168f2d0",
					},
				},
				{
					ID: "org.example:example-nested-scope-empty:1.0.0::2e0c37ea",
					DependsOn: []string{
						"org.example:example-scope-empty:2.0.0::af2c22db",
					},
				},
				{
					ID: "org.example:example-nested-scope-runtime:1.0.0::98ee0b26",
					DependsOn: []string{
						"org.example:example-scope-runtime:2.0.0::acf8ee16",
					},
				},
				{
					ID: "org.example:example-scope-compile:2.0.0::e168f2d0",
					DependsOn: []string{
						"org.example:example-api-compile:3.0.0::d4015fba",
					},
				},
				{
					ID: "org.example:example-scope-empty:2.0.0::af2c22db",
					DependsOn: []string{
						"org.example:example-api-empty:3.0.0::9575d06c",
					},
				},
				{
					ID: "org.example:example-scope-runtime:2.0.0::acf8ee16",
					DependsOn: []string{
						"org.example:example-api-runtime:3.0.0::91cf1740",
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
					ID:           "com.example:inherit-scopes-in-children-from-root:0.0.1::3dbc8566",
					Name:         "com.example:inherit-scopes-in-children-from-root",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("e66ec05e", 51, 56),
				exampleNestedScopeEmpty("4c11808b", 57, 61),
				exampleNestedScopeRuntime("61fda3e9", 45, 50),
				exampleApiRuntime("95f677d8"),
				exampleScopeCompile("1d3ae149"),
				exampleScopeEmpty("7e01cb21"),
				exampleScopeRuntime("aaaa5004"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:inherit-scopes-in-children-from-root:0.0.1::3dbc8566",
					DependsOn: []string{
						"org.example:example-nested-scope-compile:1.0.0::e66ec05e",
						"org.example:example-nested-scope-empty:1.0.0::4c11808b",
						"org.example:example-nested-scope-runtime:1.0.0::61fda3e9",
					},
				},
				{
					ID: "org.example:example-nested-scope-compile:1.0.0::e66ec05e",
					DependsOn: []string{
						"org.example:example-scope-compile:2.0.0::1d3ae149",
					},
				},
				{
					ID: "org.example:example-nested-scope-empty:1.0.0::4c11808b",
					DependsOn: []string{
						"org.example:example-scope-empty:2.0.0::7e01cb21",
					},
				},
				{
					ID: "org.example:example-nested-scope-runtime:1.0.0::61fda3e9",
					DependsOn: []string{
						"org.example:example-scope-runtime:2.0.0::aaaa5004",
					},
				},
				{
					ID: "org.example:example-scope-runtime:2.0.0::aaaa5004",
					DependsOn: []string{
						"org.example:example-api-runtime:3.0.0::95f677d8",
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
					ID:           "com.example:inherit-scopes-in-parents-from-root:0.1.0::ac1ed632",
					Name:         "com.example:inherit-scopes-in-parents-from-root",
					Version:      "0.1.0",
					Relationship: ftypes.RelationshipRoot,
				},
				exampleNestedScopeCompile("4ce69e4d", 0, 0),
				exampleNestedScopeRuntime("9660d657", 0, 0),
				exampleApiRuntime("efcdf95e"),
				exampleScopeCompile("c30b48fb"),
				exampleScopeRuntime("ea3219cb"),
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:inherit-scopes-in-parents-from-root:0.1.0::ac1ed632",
					DependsOn: []string{
						"org.example:example-nested-scope-compile:1.0.0::4ce69e4d",
						"org.example:example-nested-scope-runtime:1.0.0::9660d657",
					},
				},
				{
					ID: "org.example:example-nested-scope-compile:1.0.0::4ce69e4d",
					DependsOn: []string{
						"org.example:example-scope-compile:2.0.0::c30b48fb",
					},
				},
				{
					ID: "org.example:example-nested-scope-runtime:1.0.0::9660d657",
					DependsOn: []string{
						"org.example:example-scope-runtime:2.0.0::ea3219cb",
					},
				},
				{
					ID: "org.example:example-scope-runtime:2.0.0::ea3219cb",
					DependsOn: []string{
						"org.example:example-api-runtime:3.0.0::efcdf95e",
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
					ID:           "com.example:root-pom-with-spaces:1.0.0::eae09abe",
					Name:         "com.example:root-pom-with-spaces",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-nested:3.3.3::11f4a96e",
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
					ID:           "org.example:example-api:2.0.0::c9934860",
					Name:         "org.example:example-api",
					Version:      "2.0.0",
					Licenses:     []string{"The Apache Software License, Version 2.0"},
					Relationship: ftypes.RelationshipIndirect,
				},
				// dependency version is taken from `com.example:root-pom-with-spaces` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:           "org.example:example-dependency:1.2.4::13e3505f",
					Name:         "org.example:example-dependency",
					Version:      "1.2.4",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:root-pom-with-spaces:1.0.0::eae09abe",
					DependsOn: []string{
						"org.example:example-nested:3.3.3::11f4a96e",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.4::13e3505f",
					DependsOn: []string{
						"org.example:example-api:2.0.0::c9934860",
					},
				},
				{
					ID: "org.example:example-nested:3.3.3::11f4a96e",
					DependsOn: []string{
						"org.example:example-dependency:1.2.4::13e3505f",
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
					ID:           "com.example:get-fields-from-multiple-depmanagements:1.0.0::6c3b7d0c",
					Name:         "com.example:get-fields-from-multiple-depmanagements",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					ID:           "org.example:example-dependency:4.0.0::1c05143b",
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
					ID:           "org.example:example-api4:4.0.0::faae46bb",
					Name:         "org.example:example-api4",
					Version:      "4.0.0",
					Relationship: ftypes.RelationshipIndirect,
				},
				{
					ID:           "org.example:example-api6:1.7.30::779e4060",
					Name:         "org.example:example-api6",
					Version:      "1.7.30",
					Relationship: ftypes.RelationshipIndirect,
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "com.example:get-fields-from-multiple-depmanagements:1.0.0::6c3b7d0c",
					DependsOn: []string{
						"org.example:example-dependency:4.0.0::1c05143b",
					},
				},
				{
					ID: "org.example:example-dependency:4.0.0::1c05143b",
					DependsOn: []string{
						"org.example:example-api4:4.0.0::faae46bb",
						"org.example:example-api6:1.7.30::779e4060",
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

// TestPom_Parse_Remote_Repos verifies that POM files are fetched from the correct repositories.
// The verification is done through the license field, as it's the only way to deterministically
// identify which repository an artifact came from.
func TestPom_Parse_Remote_Repos(t *testing.T) {
	const rootRepoPlaceholder = "REPO_ROOT_URL"

	tests := []struct {
		name          string
		inputFile     string
		rootRepoTxtar string            // txtar file for root repository
		repos         map[string]string // key: repository URL placeholder, value: txtar file path
		wantPackages  map[string]string
	}{
		{
			name:          "different repos for different dependencies",
			inputFile:     filepath.Join("testdata", "different-repos-for-different-poms", "pom.xml"),
			rootRepoTxtar: filepath.Join("testdata", "different-repos-for-different-poms", "repo-root-artifacts.txtar"),
			repos: map[string]string{
				"REPO1_URL": filepath.Join("testdata", "different-repos-for-different-poms", "repo1-artifacts.txtar"),
				"REPO2_URL": filepath.Join("testdata", "different-repos-for-different-poms", "repo2-artifacts.txtar"),
			},
			wantPackages: map[string]string{
				"org.example:example-api:1.7.30::2cbe1ca4": "License from repo1",
				"org.example:example-api2:1.0.0::f8958ec7": "License from repo2",
				"org.example:example-api3:1.0.0::887fc940": "License from reporoot",
			},
		},
		{
			name:          "root POM with module inherits repository",
			inputFile:     filepath.Join("testdata", "repo-from-root-for-dep-from-module", "pom.xml"),
			rootRepoTxtar: filepath.Join("testdata", "repo-from-root-for-dep-from-module", "repo-artifacts.txtar"),
			repos:         nil,
			wantPackages: map[string]string{
				"org.example:example-api:1.0.0::4a790a84": "License from root repo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup remote repositories from txtar files
			repoURLs := make(map[string]string)
			for placeholder, txtarPath := range tt.repos {
				repoURL := setupTxtarRepository(t, txtarPath, nil)
				repoURLs[placeholder] = repoURL
			}

			// Setup root repository with replacements for repo placeholders
			rootRepoURL := setupTxtarRepository(t, tt.rootRepoTxtar, repoURLs)

			// Prepare input POM file with root repository URL
			pomContent := applyReplacements(t, tt.inputFile, map[string]string{
				rootRepoPlaceholder: rootRepoURL,
			})

			// Parse the POM
			parser := pom.NewParser(tt.inputFile)
			pkgs, _, err := parser.Parse(t.Context(), bytes.NewReader(pomContent))
			require.NoError(t, err)

			// Verify expected packages
			for pkgID, wantLicense := range tt.wantPackages {
				p, found := lo.Find(pkgs, func(pkg ftypes.Package) bool {
					return pkg.ID == pkgID
				})
				require.True(t, found, "package %s not found", pkgID)
				require.NotEmpty(t, p.Licenses, "package %s has no licenses", pkgID)
				require.Equal(t, wantLicense, p.Licenses[0])
			}
		})
	}
}

// applyReplacements reads a file, applies replacements, and returns the modified content.
func applyReplacements(t *testing.T, filePath string, replacements map[string]string) []byte {
	t.Helper()

	content, err := os.ReadFile(filePath)
	require.NoError(t, err)

	for oldURL, newURL := range replacements {
		content = bytes.ReplaceAll(content, []byte(oldURL), []byte(newURL))
	}

	return content
}

// txtarWithReposReplace reads a txtar file, applies repository URL replacements,
// and returns the result as a fs.FS.
func txtarWithReposReplace(t *testing.T, txtarPath string, reposReplacements map[string]string) fs.FS {
	t.Helper()

	content := applyReplacements(t, txtarPath, reposReplacements)

	archive := txtar.Parse(content)

	fsys, err := txtar.FS(archive)
	require.NoError(t, err)

	return fsys
}

// setupTxtarRepository reads a txtar file, applies repository URL replacements,
// starts an HTTP test server with the files, and returns the server URL.
func setupTxtarRepository(t *testing.T, txtarPath string, reposReplacements map[string]string) string {
	t.Helper()

	fsys := txtarWithReposReplace(t, txtarPath, reposReplacements)

	ts := httptest.NewServer(http.FileServer(http.FS(fsys)))
	t.Cleanup(ts.Close)

	return ts.URL
}
