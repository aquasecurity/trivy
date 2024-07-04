package composer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	// docker run --name composer --rm -it composer@sha256:082ed124b68e7e880721772a6bf22ad809e3bc87db8bbee9f0ec7127bb21ccad bash
	// apk add jq
	// composer require guzzlehttp/guzzle:6.5.8
	// composer require pear/log:1.13.3 --dev
	// composer show -i --no-dev -f json | jq --sort-keys -rc '.installed[] | "{ID: \"\(.name)@\(.version)\", Name: \"\(.name)\", Version: \"\(.version)\", License: \"MIT\", Locations: []ftypes.Location{{StartLine: , EndLine: }}},"'
	// locations are filled manually
	composerPkgs = []ftypes.Package{
		{
			ID:       "guzzlehttp/guzzle@6.5.8",
			Name:     "guzzlehttp/guzzle",
			Version:  "6.5.8",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 9,
					EndLine:   123,
				},
			},
		},
		{
			ID:       "guzzlehttp/promises@1.5.2",
			Name:     "guzzlehttp/promises",
			Version:  "1.5.2",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 124,
					EndLine:   207,
				},
			},
		},
		{
			ID:       "guzzlehttp/psr7@1.9.0",
			Name:     "guzzlehttp/psr7",
			Version:  "1.9.0",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 208,
					EndLine:   317,
				},
			},
		},
		{
			ID:       "psr/http-message@1.0.1",
			Name:     "psr/http-message",
			Version:  "1.0.1",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 318,
					EndLine:   370,
				},
			},
		},
		{
			ID:       "ralouphie/getallheaders@3.0.3",
			Name:     "ralouphie/getallheaders",
			Version:  "3.0.3",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 371,
					EndLine:   414,
				},
			},
		},
		{
			ID:       "symfony/polyfill-intl-idn@v1.27.0",
			Name:     "symfony/polyfill-intl-idn",
			Version:  "v1.27.0",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 415,
					EndLine:   501,
				},
			},
		},
		{
			ID:       "symfony/polyfill-intl-normalizer@v1.27.0",
			Name:     "symfony/polyfill-intl-normalizer",
			Version:  "v1.27.0",
			Licenses: []string{"MIT"},
			Locations: []ftypes.Location{
				{
					StartLine: 502,
					EndLine:   583,
				},
			},
		},
		{
			ID:       "symfony/polyfill-php72@v1.27.0",
			Name:     "symfony/polyfill-php72",
			Version:  "v1.27.0",
			Licenses: []string{"MIT", "BSD-2-Clause"},
			Locations: []ftypes.Location{
				{
					StartLine: 584,
					EndLine:   657,
				},
			},
		},
	}
	// dependencies are filled manually
	composerDeps = []ftypes.Dependency{
		{
			ID: "guzzlehttp/guzzle@6.5.8",
			DependsOn: []string{
				"guzzlehttp/promises@1.5.2",
				"guzzlehttp/psr7@1.9.0",
				"symfony/polyfill-intl-idn@v1.27.0",
			},
		},
		{
			ID: "guzzlehttp/psr7@1.9.0",
			DependsOn: []string{
				"psr/http-message@1.0.1",
				"ralouphie/getallheaders@3.0.3",
			},
		},
		{
			ID: "symfony/polyfill-intl-idn@v1.27.0",
			DependsOn: []string{
				"symfony/polyfill-intl-normalizer@v1.27.0",
				"symfony/polyfill-php72@v1.27.0",
			},
		},
	}
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
	}{
		{
			name:     "happy path",
			file:     "testdata/composer_happy.lock",
			wantPkgs: composerPkgs,
			wantDeps: composerDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, gotDeps, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
