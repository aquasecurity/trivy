package sum

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string
		want []ftypes.Package
	}{
		{
			file: "testdata/gomod_normal.sum",
			want: GoModNormal,
		},
		{
			file: "testdata/gomod_emptyline.sum",
			want: GoModEmptyLine,
		},
		{
			file: "testdata/gomod_many.sum",
			want: GoModMany,
		},
		{
			file: "testdata/gomod_trivy.sum",
			want: GoModTrivy,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := NewParser().Parse(t.Context(), f)
			require.NoError(t, err)

			for i := range got {
				got[i].ID = "" // Not compare IDs, tested in mod.TestModuleID()
			}

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)
		})
	}
}

func TestParseDigests(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[module.Version]digest.Digest
	}{
		{
			name: "module and go.mod entries",
			input: `golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=
golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=`,
			want: map[module.Version]digest.Digest{
				{Path: "golang.org/x/xerrors", Version: "v0.0.0-20200804184101-5ec99f83aff1"}: "sha256:828d5b2bf0ff045655d88f1c21077534a119fb4a304931b57c34dc8b822a15c1",
			},
		},
		{
			name:  "go.mod entry only",
			input: `gopkg.in/yaml.v2 v2.2.2/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=`,
			want:  map[module.Version]digest.Digest{},
		},
		{
			name: "several versions of one module",
			input: `github.com/BurntSushi/toml v0.3.1 h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=
github.com/BurntSushi/toml v0.4.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
			want: map[module.Version]digest.Digest{
				{Path: "github.com/BurntSushi/toml", Version: "v0.3.1"}: "sha256:597918625e98af7a817f52bbf440672f899a9343a29817c1d1751ff55976f0e4",
				{Path: "github.com/BurntSushi/toml", Version: "v0.4.0"}: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
		{
			name: "malformed entries",
			input: `example.com/no-hash v1.0.0
example.com/h2 v1.0.0 h2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
example.com/bad-base64 v1.0.0 h1:!!!
example.com/short v1.0.0 h1:AAAA
example.com/empty v1.0.0 h1:`,
			want: map[module.Version]digest.Digest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDigests(strings.NewReader(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
