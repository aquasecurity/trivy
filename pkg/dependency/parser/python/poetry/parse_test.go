package poetry

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantLibs []types.Library
		wantDeps []types.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "normal",
			file:     "testdata/poetry_normal.lock",
			wantLibs: poetryNormal,
			wantErr:  assert.NoError,
		},
		{
			name:     "many",
			file:     "testdata/poetry_many.lock",
			wantLibs: poetryMany,
			wantDeps: poetryManyDeps,
			wantErr:  assert.NoError,
		},
		{
			name:     "flask",
			file:     "testdata/poetry_flask.lock",
			wantLibs: poetryFlask,
			wantDeps: poetryFlaskDeps,
			wantErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := &Parser{}
			gotLibs, gotDeps, err := p.Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.wantLibs, gotLibs, "Parse(%v)", tt.file)
			assert.Equalf(t, tt.wantDeps, gotDeps, "Parse(%v)", tt.file)
		})
	}
}

func TestParseDependency(t *testing.T) {
	tests := []struct {
		name         string
		packageName  string
		versionRange interface{}
		libsVersions map[string][]string
		want         string
		wantErr      string
	}{
		{
			name:         "handle package name",
			packageName:  "Test_project.Name",
			versionRange: "*",
			libsVersions: map[string][]string{
				"test-project-name": {"1.0.0"},
			},
			want: "test-project-name@1.0.0",
		},
		{
			name:         "version range as string",
			packageName:  "test",
			versionRange: ">=1.0.0",
			libsVersions: map[string][]string{
				"test": {"2.0.0"},
			},
			want: "test@2.0.0",
		},
		{
			name:         "version range == *",
			packageName:  "test",
			versionRange: "*",
			libsVersions: map[string][]string{
				"test": {"3.0.0"},
			},
			want: "test@3.0.0",
		},
		{
			name:        "version range as json",
			packageName: "test",
			versionRange: map[string]interface{}{
				"version": ">=4.8.3",
				"markers": "python_version < \"3.8\"",
			},
			libsVersions: map[string][]string{
				"test": {"5.0.0"},
			},
			want: "test@5.0.0",
		},
		{
			name:         "libsVersions doesn't contain required version",
			packageName:  "test",
			versionRange: ">=1.0.0",
			libsVersions: map[string][]string{},
			wantErr:      "no version found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDependency(tt.packageName, tt.versionRange, tt.libsVersions)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
