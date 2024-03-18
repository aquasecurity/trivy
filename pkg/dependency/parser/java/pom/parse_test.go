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
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestPom_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		local     bool
		offline   bool
		want      []types.Library
		wantDeps  []types.Dependency
		wantErr   string
	}{
		{
			name:      "local repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:happy:1.0.0",
					Name:    "com.example:happy",
					Version: "1.0.0",
					License: "BSD-3-Clause",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:      "org.example:example-runtime:1.0.0",
					Name:    "org.example:example-runtime",
					Version: "1.0.0",
					Locations: types.Locations{
						{
							StartLine: 37,
							EndLine:   42,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:happy:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
						"org.example:example-runtime:1.0.0",
					},
				},
			},
		},
		{
			name:      "remote repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					ID:      "com.example:happy:1.0.0",
					Name:    "com.example:happy",
					Version: "1.0.0",
					License: "BSD-3-Clause",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:      "org.example:example-runtime:1.0.0",
					Name:    "org.example:example-runtime",
					Version: "1.0.0",
					Locations: types.Locations{
						{
							StartLine: 37,
							EndLine:   42,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:happy:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
						"org.example:example-runtime:1.0.0",
					},
				},
			},
		},
		{
			name:      "offline mode",
			inputFile: filepath.Join("testdata", "offline", "pom.xml"),
			local:     false,
			offline:   true,
			want: []types.Library{
				{
					ID:      "org.example:example-offline:2.3.4",
					Name:    "org.example:example-offline",
					Version: "2.3.4",
					Locations: types.Locations{
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
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0",
					Name:    "com.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 33,
							EndLine:   37,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "inherit project properties from parent",
			inputFile: filepath.Join("testdata", "project-version-from-parent", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:child:2.0.0",
					Name:    "com.example:child",
					Version: "2.0.0",
				},
				{
					ID:      "org.example:example-api:2.0.0",
					Name:    "org.example:example-api",
					Version: "2.0.0",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 18,
							EndLine:   22,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:2.0.0",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
			},
		},
		{
			name:      "inherit properties in parent depManagement with import scope",
			inputFile: filepath.Join("testdata", "inherit-props", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:test:0.0.1-SNAPSHOT",
					Name:    "com.example:test",
					Version: "0.0.1-SNAPSHOT",
				},
				{
					ID:      "org.example:example-api:2.0.0",
					Name:    "org.example:example-api",
					Version: "2.0.0",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 18,
							EndLine:   21,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:test:0.0.1-SNAPSHOT",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
			},
		},
		{
			name:      "dependencyManagement prefers child properties",
			inputFile: filepath.Join("testdata", "parent-child-properties", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0",
					Name:    "com.example:child",
					Version: "1.0.0",
				},
				{
					ID:       "org.example:example-api:4.0.0",
					Name:     "org.example:example-api",
					Version:  "4.0.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
					Locations: types.Locations{
						{
							StartLine: 22,
							EndLine:   26,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:1.0.0",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:4.0.0",
					},
				},
			},
		},
		{
			name:      "inherit parent dependencies",
			inputFile: filepath.Join("testdata", "parent-dependencies", "child", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0-SNAPSHOT",
					Name:    "com.example:child",
					Version: "1.0.0-SNAPSHOT",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:1.0.0-SNAPSHOT",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "inherit parent dependencyManagement",
			inputFile: filepath.Join("testdata", "parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:child:3.0.0",
					Name:    "com.example:child",
					Version: "3.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 26,
							EndLine:   29,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:3.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "transitive parents",
			inputFile: filepath.Join("testdata", "transitive-parents", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:base:4.0.0",
					Name:    "com.example:base",
					Version: "4.0.0",
					License: "Apache 2.0",
				},
				{
					ID:       "org.example:example-api:1.7.30",
					Name:     "org.example:example-api",
					Version:  "1.7.30",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-child:2.0.0",
					Name:    "org.example:example-child",
					Version: "2.0.0",
					License: "Apache 2.0",
					Locations: types.Locations{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:base:4.0.0",
					DependsOn: []string{
						"org.example:example-child:2.0.0",
					},
				},
				{
					ID: "org.example:example-child:2.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "parent relativePath",
			inputFile: filepath.Join("testdata", "parent-relative-path", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0",
					Name:    "com.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 26,
							EndLine:   30,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "parent version in property",
			inputFile: filepath.Join("testdata", "parent-version-is-property", "child", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0-SNAPSHOT",
					Name:    "com.example:child",
					Version: "1.0.0-SNAPSHOT",
				},
				{
					ID:      "org.example:example-api:1.1.1",
					Name:    "org.example:example-api",
					Version: "1.1.1",
					Locations: types.Locations{
						{
							StartLine: 19,
							EndLine:   22,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:child:1.0.0-SNAPSHOT",
					DependsOn: []string{
						"org.example:example-api:1.1.1",
					},
				},
			},
		},
		{
			name:      "parent in a remote repository",
			inputFile: filepath.Join("testdata", "parent-remote-repository", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "org.example:child:1.0.0",
					Name:    "org.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 25,
							EndLine:   29,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "org.example:child:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			// mvn dependency:tree
			// [INFO] com.example:soft:jar:1.0.0
			// [INFO] +- org.example:example-api:jar:1.7.30:compile
			// [INFO] \- org.example:example-dependency:jar:1.2.3:compile
			// Save DependsOn for each library - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "soft requirement",
			inputFile: filepath.Join("testdata", "soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:soft:1.0.0",
					Name:    "com.example:soft",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 32,
							EndLine:   36,
						},
					},
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
					Locations: types.Locations{
						{
							StartLine: 37,
							EndLine:   41,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:soft:1.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
						"org.example:example-dependency:1.2.3",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
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
			// Save DependsOn for each library - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "soft requirement with transitive dependencies",
			inputFile: filepath.Join("testdata", "soft-requirement-with-transitive-dependencies", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:soft-transitive:1.0.0",
					Name:    "com.example:soft-transitive",
					Version: "1.0.0",
				},
				{
					ID:       "org.example:example-api:2.0.0",
					Name:     "org.example:example-api",
					Version:  "2.0.0",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-dependency2:2.3.4",
					Name:    "org.example:example-dependency2",
					Version: "2.3.4",
					Locations: types.Locations{
						{
							StartLine: 18,
							EndLine:   22,
						},
					},
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
					Locations: types.Locations{
						{
							StartLine: 13,
							EndLine:   17,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:soft-transitive:1.0.0",
					DependsOn: []string{
						"org.example:example-dependency2:2.3.4",
						"org.example:example-dependency:1.2.3",
					},
				},
				{
					ID: "org.example:example-dependency2:2.3.4",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
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
			// Save DependsOn for each library - https://github.com/aquasecurity/go-dep-parser/pull/243#discussion_r1303904548
			name:      "hard requirement for the specified version",
			inputFile: filepath.Join("testdata", "hard-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:hard:1.0.0",
					Name:    "com.example:hard",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:       "org.example:example-api:2.0.0",
					Name:     "org.example:example-api",
					Version:  "2.0.0",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
					Locations: types.Locations{
						{
							StartLine: 33,
							EndLine:   37,
						},
					},
				},
				{
					ID:      "org.example:example-nested:3.3.4",
					Name:    "org.example:example-nested",
					Version: "3.3.4",
					Locations: types.Locations{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:hard:1.0.0",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
						"org.example:example-nested:3.3.4",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
				{
					ID: "org.example:example-nested:3.3.4",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
					},
				},
			},
		},
		{
			name:      "version requirement",
			inputFile: filepath.Join("testdata", "version-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:hard:1.0.0",
					Name:    "com.example:hard",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
			},
		},
		{
			name:      "import dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:import:2.0.0",
					Name:    "com.example:import",
					Version: "2.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 34,
							EndLine:   37,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:import:2.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "import multiple dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management-multiple", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:import:2.0.0",
					Name:    "com.example:import",
					Version: "2.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 42,
							EndLine:   45,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:import:2.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "exclusions",
			inputFile: filepath.Join("testdata", "exclusions", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:exclusions:3.0.0",
					Name:    "com.example:exclusions",
					Version: "3.0.0",
				},
				{
					ID:       "org.example:example-dependency:1.2.3",
					Name:     "org.example:example-dependency",
					Version:  "1.2.3",
					Indirect: true,
				},
				{
					ID:      "org.example:example-nested:3.3.3",
					Name:    "org.example:example-nested",
					Version: "3.3.3",
					Locations: types.Locations{
						{
							StartLine: 14,
							EndLine:   28,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:exclusions:3.0.0",
					DependsOn: []string{
						"org.example:example-nested:3.3.3",
					},
				},
				{
					ID: "org.example:example-nested:3.3.3",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
					},
				},
			},
		},
		{
			name:      "exclusions in child",
			inputFile: filepath.Join("testdata", "exclusions-in-child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:example:1.0.0",
					Name:    "com.example:example",
					Version: "1.0.0",
				},
				{
					ID:       "org.example:example-api:1.7.30",
					Name:     "org.example:example-api",
					Version:  "1.7.30",
					Indirect: true,
					License:  "The Apache Software License, Version 2.0",
				},
				{
					ID:       "org.example:example-dependency:1.2.3",
					Name:     "org.example:example-dependency",
					Version:  "1.2.3",
					Indirect: true,
				},
				{
					ID:      "org.example:example-exclusions:4.0.0",
					Name:    "org.example:example-exclusions",
					Version: "4.0.0",
					Locations: types.Locations{
						{
							StartLine: 10,
							EndLine:   14,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:example:1.0.0",
					DependsOn: []string{
						"org.example:example-exclusions:4.0.0",
					},
				},
				{
					ID: "org.example:example-exclusions:4.0.0",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
						"org.example:example-dependency:1.2.3",
					},
				},
			},
		},
		{
			name:      "exclusions with wildcards",
			inputFile: filepath.Join("testdata", "wildcard-exclusions", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:wildcard-exclusions:4.0.0",
					Name:    "com.example:wildcard-exclusions",
					Version: "4.0.0",
				},
				{
					ID:      "org.example:example-dependency2:2.3.4",
					Name:    "org.example:example-dependency2",
					Version: "2.3.4",
					Locations: types.Locations{
						{
							StartLine: 25,
							EndLine:   35,
						},
					},
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
					Locations: types.Locations{
						{
							StartLine: 14,
							EndLine:   24,
						},
					},
				},
				{
					ID:      "org.example:example-nested:3.3.3",
					Name:    "org.example:example-nested",
					Version: "3.3.3",
					Locations: types.Locations{
						{
							StartLine: 36,
							EndLine:   46,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:wildcard-exclusions:4.0.0",
					DependsOn: []string{
						"org.example:example-dependency2:2.3.4",
						"org.example:example-dependency:1.2.3",
						"org.example:example-nested:3.3.3",
					},
				},
			},
		},
		{
			name:      "multi module",
			inputFile: filepath.Join("testdata", "multi-module", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:aggregation:1.0.0",
					Name:    "com.example:aggregation",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "com.example:module:1.1.1",
					Name:    "com.example:module",
					Version: "1.1.1",
					License: "Apache 2.0",
				},
				{
					ID:       "org.example:example-api:2.0.0",
					Name:     "org.example:example-api",
					Version:  "2.0.0",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-dependency:1.2.3",
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
			},
			// maven doesn't include modules in dep tree of root pom
			// for modules uses separate graph:
			// ➜ mvn dependency:tree
			// [INFO] --------------------------------[ jar ]---------------------------------
			// [INFO]
			// [INFO] --- dependency:3.6.0:tree (default-cli) @ module ---
			// [INFO] com.example:module:jar:1.1.1
			// [INFO] \- org.example:example-dependency:jar:1.2.3:compile
			// [INFO]    \- org.example:example-api:jar:2.0.0:compile
			// [INFO]
			// [INFO] ----------------------< com.example:aggregation >-----------------------
			// [INFO] Building aggregation 1.0.0                                         [2/2]
			// [INFO]   from pom.xml
			// [INFO] --------------------------------[ pom ]---------------------------------
			// [INFO]
			// [INFO] --- dependency:3.6.0:tree (default-cli) @ aggregation ---
			// [INFO] com.example:aggregation:pom:1.0.0
			wantDeps: []types.Dependency{
				{
					ID: "com.example:module:1.1.1",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
			},
		},
		{
			name:      "multi module soft requirement",
			inputFile: filepath.Join("testdata", "multi-module-soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:aggregation:1.0.0",
					Name:    "com.example:aggregation",
					Version: "1.0.0",
				},
				{
					ID:      "com.example:module1:1.1.1",
					Name:    "com.example:module1",
					Version: "1.1.1",
				},
				{
					ID:      "com.example:module2:1.1.1",
					Name:    "com.example:module2",
					Version: "1.1.1",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
				},
				{
					ID:      "org.example:example-api:2.0.0",
					Name:    "org.example:example-api",
					Version: "2.0.0",
					License: "The Apache Software License, Version 2.0",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:module1:1.1.1",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
				{
					ID: "com.example:module2:1.1.1",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
			},
		},
		{
			name:      "overwrite artifact version from dependencyManagement in the root POM",
			inputFile: filepath.Join("testdata", "root-pom-dep-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:root-pom-dep-management:1.0.0",
					Name:    "com.example:root-pom-dep-management",
					Version: "1.0.0",
				},
				{
					ID:       "org.example:example-api:2.0.0",
					Name:     "org.example:example-api",
					Version:  "2.0.0",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					ID:       "org.example:example-dependency:1.2.4",
					Name:     "org.example:example-dependency",
					Version:  "1.2.4",
					Indirect: true,
				},
				{
					ID:      "org.example:example-nested:3.3.3",
					Name:    "org.example:example-nested",
					Version: "3.3.3",
					Locations: types.Locations{
						{
							StartLine: 20,
							EndLine:   24,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:root-pom-dep-management:1.0.0",
					DependsOn: []string{
						"org.example:example-nested:3.3.3",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.4",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
				{
					ID: "org.example:example-nested:3.3.3",
					DependsOn: []string{
						"org.example:example-dependency:1.2.4",
					},
				},
			},
		},
		{
			name:      "transitive dependencyManagement should not be inherited",
			inputFile: filepath.Join("testdata", "transitive-dependency-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				// Managed dependencies (org.example:example-api:1.7.30) in org.example:example-dependency-management3
				// should not affect dependencies of example-dependency (org.example:example-api:2.0.0)
				{
					ID:       "org.example:example-api:2.0.0",
					Name:     "org.example:example-api",
					Version:  "2.0.0",
					License:  "The Apache Software License, Version 2.0",
					Indirect: true,
				},
				{
					ID:      "org.example:example-dependency-management3:1.1.1",
					Name:    "org.example:example-dependency-management3",
					Version: "1.1.1",
					Locations: types.Locations{
						{
							StartLine: 14,
							EndLine:   18,
						},
					},
				},
				{
					ID:       "org.example:example-dependency:1.2.3",
					Name:     "org.example:example-dependency",
					Version:  "1.2.3",
					Indirect: true,
				},
				{
					ID:      "org.example:transitive-dependency-management:2.0.0",
					Name:    "org.example:transitive-dependency-management",
					Version: "2.0.0",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "org.example:example-dependency-management3:1.1.1",
					DependsOn: []string{
						"org.example:example-dependency:1.2.3",
					},
				},
				{
					ID: "org.example:example-dependency:1.2.3",
					DependsOn: []string{
						"org.example:example-api:2.0.0",
					},
				},
				{
					ID: "org.example:transitive-dependency-management:2.0.0",
					DependsOn: []string{
						"org.example:example-dependency-management3:1.1.1",
					},
				},
			},
		},
		{
			name:      "parent not found",
			inputFile: filepath.Join("testdata", "not-found-parent", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:no-parent:1.0-SNAPSHOT",
					Name:    "com.example:no-parent",
					Version: "1.0-SNAPSHOT",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-api:1.7.30",
					Name:    "org.example:example-api",
					Version: "1.7.30",
					License: "The Apache Software License, Version 2.0",
					Locations: types.Locations{
						{
							StartLine: 27,
							EndLine:   31,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:no-parent:1.0-SNAPSHOT",
					DependsOn: []string{
						"org.example:example-api:1.7.30",
					},
				},
			},
		},
		{
			name:      "dependency not found",
			inputFile: filepath.Join("testdata", "not-found-dependency", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:not-found-dependency:1.0.0",
					Name:    "com.example:not-found-dependency",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					ID:      "org.example:example-not-found:999",
					Name:    "org.example:example-not-found",
					Version: "999",
					Locations: types.Locations{
						{
							StartLine: 21,
							EndLine:   25,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
				{
					ID: "com.example:not-found-dependency:1.0.0",
					DependsOn: []string{
						"org.example:example-not-found:999",
					},
				},
			},
		},
		{
			name:      "module not found - unable to parse module",
			inputFile: filepath.Join("testdata", "not-found-module", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:aggregation:1.0.0",
					Name:    "com.example:aggregation",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
			},
		},
		{
			name:      "multiply licenses",
			inputFile: filepath.Join("testdata", "multiply-licenses", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:multiply-licenses:1.0.0",
					Name:    "com.example:multiply-licenses",
					Version: "1.0.0",
					License: "MIT, Apache 2.0",
				},
			},
		},
		{
			name:      "inherit parent license",
			inputFile: filepath.Join("testdata", "inherit-license", "module", "submodule", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example.app:submodule:1.0.0",
					Name:    "com.example.app:submodule",
					Version: "1.0.0",
					License: "Apache-2.0",
				},
			},
		},
		{
			name:      "compare ArtifactIDs for base and parent pom's",
			inputFile: filepath.Join("testdata", "no-parent-infinity-loop", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					ID:      "com.example:child:1.0.0",
					Name:    "com.example:child",
					Version: "1.0.0",
					License: "The Apache Software License, Version 2.0",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			p := pom.NewParser(tt.inputFile, pom.WithRemoteRepos(remoteRepos), pom.WithOffline(tt.offline))

			gotLibs, gotDeps, err := p.Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, gotLibs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
