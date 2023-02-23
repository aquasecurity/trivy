package bundler_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/ruby/bundler"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	NormalLibs = []types.Library{
		{
			ID:       "coderay@1.1.2",
			Name:     "coderay",
			Version:  "1.1.2",
			Indirect: true,
		},
		{
			ID:       "concurrent-ruby@1.1.5",
			Name:     "concurrent-ruby",
			Version:  "1.1.5",
			Indirect: true,
		},
		{
			ID:      "dotenv@2.7.2",
			Name:    "dotenv",
			Version: "2.7.2",
		},
		{
			ID:      "faker@1.9.3",
			Name:    "faker",
			Version: "1.9.3",
		},
		{
			ID:       "i18n@1.6.0",
			Name:     "i18n",
			Version:  "1.6.0",
			Indirect: true,
		},
		{
			ID:       "method_source@0.9.2",
			Name:     "method_source",
			Version:  "0.9.2",
			Indirect: true,
		},
		{
			ID:      "pry@0.12.2",
			Name:    "pry",
			Version: "0.12.2",
		},
	}
	NormalDeps = []types.Dependency{
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
	Bundler2Libs = []types.Library{
		{
			ID:       "coderay@1.1.3",
			Name:     "coderay",
			Version:  "1.1.3",
			Indirect: true,
		},
		{
			ID:       "concurrent-ruby@1.1.10",
			Name:     "concurrent-ruby",
			Version:  "1.1.10",
			Indirect: true,
		},
		{
			ID:      "dotenv@2.7.6",
			Name:    "dotenv",
			Version: "2.7.6",
		},
		{
			ID:      "faker@2.21.0",
			Name:    "faker",
			Version: "2.21.0",
		},
		{
			ID:       "i18n@1.10.0",
			Name:     "i18n",
			Version:  "1.10.0",
			Indirect: true,
		},
		{
			ID:      "json@2.6.2",
			Name:    "json",
			Version: "2.6.2",
		},
		{
			ID:       "method_source@1.0.0",
			Name:     "method_source",
			Version:  "1.0.0",
			Indirect: true,
		},
		{
			ID:      "pry@0.14.1",
			Name:    "pry",
			Version: "0.14.1",
		},
	}
	Bundler2Deps = []types.Dependency{
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
		wantLibs []types.Library
		wantDeps []types.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "normal",
			file:     "testdata/Gemfile_normal.lock",
			wantLibs: NormalLibs,
			wantDeps: NormalDeps,
			wantErr:  assert.NoError,
		},
		{
			name:     "bundler2",
			file:     "testdata/Gemfile_bundler2.lock",
			wantLibs: Bundler2Libs,
			wantDeps: Bundler2Deps,
			wantErr:  assert.NoError,
		},
		{
			name:     "malformed",
			file:     "testdata/Gemfile_malformed.lock",
			wantLibs: []types.Library{},
			wantErr:  assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			p := &bundler.Parser{}
			gotLibs, gotDeps, err := p.Parse(f)
			if !tt.wantErr(t, err, fmt.Sprintf("Parse(%v)", tt.file)) {
				return
			}
			assert.Equalf(t, tt.wantLibs, gotLibs, "Parse(%v)", tt.file)
			assert.Equalf(t, tt.wantDeps, gotDeps, "Parse(%v)", tt.file)
		})
	}
}
