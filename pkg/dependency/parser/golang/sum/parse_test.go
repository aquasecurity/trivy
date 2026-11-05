package sum

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"

	"github.com/aquasecurity/trivy/pkg/digest"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []Entry
	}{
		{
			name: "module and go.mod lines",
			input: `golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=
golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=`,
			want: []Entry{
				{
					Module:    module.Version{Path: "golang.org/x/xerrors", Version: "v0.0.0-20200804184101-5ec99f83aff1"},
					ModuleSum: "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
				},
			},
		},
		{
			name:  "go.mod line only",
			input: `gopkg.in/yaml.v2 v2.2.2/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=`,
			want: []Entry{
				{
					Module: module.Version{Path: "gopkg.in/yaml.v2", Version: "v2.2.2"},
				},
			},
		},
		{
			name: "go.mod line before module line",
			input: `github.com/pkg/errors v0.8.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
github.com/pkg/errors v0.8.1 h1:iURUrRGxPUNPdy5/HRSm+Yj6okJ6UtLINN0Q9M4+h3I=`,
			want: []Entry{
				{
					Module:    module.Version{Path: "github.com/pkg/errors", Version: "v0.8.1"},
					ModuleSum: "h1:iURUrRGxPUNPdy5/HRSm+Yj6okJ6UtLINN0Q9M4+h3I=",
				},
			},
		},
		{
			name: "several versions of one module",
			input: `github.com/BurntSushi/toml v0.3.1 h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=
github.com/BurntSushi/toml v0.3.1/go.mod h1:xHWCNGjB5oqiDr8zfno3MHue2Ht5sIBksp03qcyfWMU=
github.com/BurntSushi/toml v0.4.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
			want: []Entry{
				{
					Module:    module.Version{Path: "github.com/BurntSushi/toml", Version: "v0.3.1"},
					ModuleSum: "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
				},
				{
					Module: module.Version{Path: "github.com/BurntSushi/toml", Version: "v0.4.0"},
				},
			},
		},
		{
			name: "empty and short lines",
			input: `
  github.com/karrick/godirwalk v1.12.0 h1:nkS4xxsjiZMvVlazd0mFyiwD4BR9f3m6LXGhM2TUx3Y=

example.com/no-version
example.com/no-hash v1.0.0
`,
			want: []Entry{
				{
					Module:    module.Version{Path: "github.com/karrick/godirwalk", Version: "v1.12.0"},
					ModuleSum: "h1:nkS4xxsjiZMvVlazd0mFyiwD4BR9f3m6LXGhM2TUx3Y=",
				},
				{
					Module: module.Version{Path: "example.com/no-hash", Version: "v1.0.0"},
				},
			},
		},
		{
			name:  "empty file",
			input: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeH1(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   digest.Digest
		wantOK bool
	}{
		{
			name:   "valid",
			input:  "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
			want:   "sha256:828d5b2bf0ff045655d88f1c21077534a119fb4a304931b57c34dc8b822a15c1",
			wantOK: true,
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "no prefix",
			input: "go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
		},
		{
			name:  "unknown prefix",
			input: "h2:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
		},
		{
			name:  "empty value",
			input: "h1:",
		},
		{
			name:  "invalid base64",
			input: "h1:!!!",
		},
		{
			name:  "not a SHA-256",
			input: "h1:AAAA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := DecodeH1(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
