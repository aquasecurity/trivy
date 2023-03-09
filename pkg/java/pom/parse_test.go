package pom_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestPom_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		local     bool
		offline   bool
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "local repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:happy",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "remote repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					Name:    "com.example:happy",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
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
					Name:    "org.example:example-offline",
					Version: "2.3.4",
				},
			},
		},
		{
			name:      "inherit parent properties",
			inputFile: filepath.Join("testdata", "parent-properties", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "inherit properties in parent depManagement with import scope",
			inputFile: filepath.Join("testdata", "inherit-props", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:test",
					Version: "0.0.1-SNAPSHOT",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "dependencyManagement prefers child properties",
			inputFile: filepath.Join("testdata", "parent-child-properties", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "4.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
			},
		},
		{
			name:      "inherit parent dependencies",
			inputFile: filepath.Join("testdata", "parent-dependencies", "child", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0-SNAPSHOT",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "inherit parent dependencyManagement",
			inputFile: filepath.Join("testdata", "parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "3.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "transitive parents",
			inputFile: filepath.Join("testdata", "transitive-parents", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:base",
					Version: "4.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-child",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "parent relativePath",
			inputFile: filepath.Join("testdata", "parent-relative-path", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "parent in a remote repository",
			inputFile: filepath.Join("testdata", "parent-remote-repository", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "org.example:child",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "soft requirement",
			inputFile: filepath.Join("testdata", "soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:soft",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
			},
		},
		{
			name:      "soft requirement with transitive dependencies",
			inputFile: filepath.Join("testdata", "soft-requirement-with-transitive-dependencies", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:soft-transitive",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-dependency2",
					Version: "2.3.4",
				},
			},
		},
		{
			name:      "hard requirement for the specified version",
			inputFile: filepath.Join("testdata", "hard-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:hard",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.4",
				},
			},
		},
		{
			name:      "version requirement",
			inputFile: filepath.Join("testdata", "version-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:hard",
					Version: "1.0.0",
				},
			},
		},
		{
			name:      "import dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:import",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "import multiple dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management-multiple", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:import",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "exclusions",
			inputFile: filepath.Join("testdata", "exclusions", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:exclusions",
					Version: "3.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-nested",
					Version: "3.3.3",
				},
			},
		},
		{
			name:      "multi module",
			inputFile: filepath.Join("testdata", "multi-module", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:aggregation",
					Version: "1.0.0",
				},
				{
					Name:    "com.example:module",
					Version: "1.1.1",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "multi module soft requirement",
			inputFile: filepath.Join("testdata", "multi-module-soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:aggregation",
					Version: "1.0.0",
				},
				{
					Name:    "com.example:module1",
					Version: "1.1.1",
				},
				{
					Name:    "com.example:module2",
					Version: "1.1.1",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "overwrite artifact version from dependencyManagement in the root POM",
			inputFile: filepath.Join("testdata", "root-pom-dep-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:root-pom-dep-management",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.4",
				},
				{
					Name:    "org.example:example-nested",
					Version: "3.3.3",
				},
			},
		},
		{
			name:      "transitive dependencyManagement should not be inherited",
			inputFile: "testdata/transitive-dependency-management/pom.xml",
			local:     true,
			want: []types.Library{
				// Managed dependencies (org.example:example-api:1.7.30) in org.example:example-dependency-management3
				// should not affect dependencies of example-dependency (org.example:example-api:2.0.0)
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-dependency-management3",
					Version: "1.1.1",
				},
				{
					Name:    "org.example:transitive-dependency-management",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "parent not found",
			inputFile: filepath.Join("testdata", "not-found-parent", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:no-parent",
					Version: "1.0-SNAPSHOT",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
			},
		},
		{
			name:      "dependency not found",
			inputFile: filepath.Join("testdata", "not-found-dependency", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:not-found-dependency",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-not-found",
					Version: "999",
				},
			},
		},
		{
			name:      "module not found",
			inputFile: filepath.Join("testdata", "not-found-module", "pom.xml"),
			local:     true,
			wantErr:   "stat testdata/not-found-module/module: no such file or directory",
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
				t.Setenv("MAVEN_HOME", "testdata")
			} else {
				// for remote repository
				h := http.FileServer(http.Dir(filepath.Join("testdata", "repository")))
				ts := httptest.NewServer(h)
				remoteRepos = []string{ts.URL}
			}

			p := pom.NewParser(tt.inputFile, pom.WithRemoteRepos(remoteRepos), pom.WithOffline(tt.offline))

			got, _, err := p.Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})

			assert.Equal(t, tt.want, got)
		})
	}
}
