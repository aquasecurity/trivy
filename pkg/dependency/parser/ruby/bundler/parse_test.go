package bundler_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/ruby/bundler"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	NormalPkgs = []ftypes.Package{
		{
			ID:           "dotenv@2.7.2",
			Name:         "dotenv",
			Version:      "2.7.2",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 6,
					EndLine:   6,
				},
			},
		},
		{
			ID:           "faker@1.9.3",
			Name:         "faker",
			Version:      "1.9.3",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 7,
					EndLine:   7,
				},
			},
		},
		{
			ID:           "pry@0.12.2",
			Name:         "pry",
			Version:      "0.12.2",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 12,
					EndLine:   12,
				},
			},
		},
		{
			ID:           "coderay@1.1.2",
			Name:         "coderay",
			Version:      "1.1.2",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
		{
			ID:           "concurrent-ruby@1.1.5",
			Name:         "concurrent-ruby",
			Version:      "1.1.5",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
		{
			ID:           "i18n@1.6.0",
			Name:         "i18n",
			Version:      "1.6.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 9,
					EndLine:   9,
				},
			},
		},
		{
			ID:           "method_source@0.9.2",
			Name:         "method_source",
			Version:      "0.9.2",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 11,
					EndLine:   11,
				},
			},
		},
	}
	NormalDeps = []ftypes.Dependency{
		{
			ID:        "faker@1.9.3",
			DependsOn: []string{"i18n@1.6.0"},
		},
		{
			ID:        "i18n@1.6.0",
			DependsOn: []string{"concurrent-ruby@1.1.5"},
		},
		{
			ID: "pry@0.12.2",
			DependsOn: []string{
				"coderay@1.1.2",
				"method_source@0.9.2",
			},
		},
	}
	Bundler2Pkgs = []ftypes.Package{
		{
			ID:           "dotenv@2.7.6",
			Name:         "dotenv",
			Version:      "2.7.6",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 6,
					EndLine:   6,
				},
			},
		},
		{
			ID:           "faker@2.21.0",
			Name:         "faker",
			Version:      "2.21.0",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 7,
					EndLine:   7,
				},
			},
		},
		{
			ID:           "json@2.6.2",
			Name:         "json",
			Version:      "2.6.2",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 11,
					EndLine:   11,
				},
			},
		},
		{
			ID:           "pry@0.14.1",
			Name:         "pry",
			Version:      "0.14.1",
			Relationship: ftypes.RelationshipDirect,
			Locations: []ftypes.Location{
				{
					StartLine: 13,
					EndLine:   13,
				},
			},
		},
		{
			ID:           "coderay@1.1.3",
			Name:         "coderay",
			Version:      "1.1.3",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
		{
			ID:           "concurrent-ruby@1.1.10",
			Name:         "concurrent-ruby",
			Version:      "1.1.10",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
		{
			ID:           "i18n@1.10.0",
			Name:         "i18n",
			Version:      "1.10.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 9,
					EndLine:   9,
				},
			},
		},
		{
			ID:           "method_source@1.0.0",
			Name:         "method_source",
			Version:      "1.0.0",
			Relationship: ftypes.RelationshipIndirect,
			Locations: []ftypes.Location{
				{
					StartLine: 12,
					EndLine:   12,
				},
			},
		},
	}
	Bundler2Deps = []ftypes.Dependency{
		{
			ID:        "faker@2.21.0",
			DependsOn: []string{"i18n@1.10.0"},
		},
		{
			ID:        "i18n@1.10.0",
			DependsOn: []string{"concurrent-ruby@1.1.10"},
		},
		{
			ID: "pry@0.14.1",
			DependsOn: []string{
				"coderay@1.1.3",
				"method_source@1.0.0",
			},
		},
	}
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "normal",
			file:     "testdata/Gemfile_normal.lock",
			wantPkgs: NormalPkgs,
			wantDeps: NormalDeps,
			wantErr:  assert.NoError,
		},
		{
			name:     "bundler2",
			file:     "testdata/Gemfile_bundler2.lock",
			wantPkgs: Bundler2Pkgs,
			wantDeps: Bundler2Deps,
			wantErr:  assert.NoError,
		},
		{
			name:     "malformed",
			file:     "testdata/Gemfile_malformed.lock",
			wantPkgs: []ftypes.Package{},
			wantErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := &bundler.Parser{}
			gotPkgs, gotDeps, err := p.Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.wantPkgs, gotPkgs, "Parse(%v)", tt.file)
			assert.Equalf(t, tt.wantDeps, gotDeps, "Parse(%v)", tt.file)
		})
	}
}
