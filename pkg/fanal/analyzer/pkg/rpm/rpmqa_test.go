package rpm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParseMarinerDistrolessManifest(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantPkgs []types.Package
		wantErr  string
	}{
		{
			name: "happy path",
			content: `mariner-release	2.0-12.cm2	1653816591	1653753130	Microsoft Corporation	(none)	580	noarch	0	mariner-release-2.0-12.cm2.src.rpm
filesystem	1.1-9.cm2	1653816591	1653628924	Microsoft Corporation	(none)	7596	x86_64	0	filesystem-1.1-9.cm2.src.rpm
glibc	2.35-2.cm2	1653816591	1653628955	Microsoft Corporation	(none)	10855265	x86_64	0	glibc-2.35-2.cm2.src.rpm
ca-certificates-base	3.0.0-8.azl3	1748892790	1735838940	Microsoft Corporation	(none)	130628	noarch	1	ca-certificates-3.0.0-8.azl3.src.rpm`,
			wantPkgs: []types.Package{
				{
					Name:       "mariner-release",
					Version:    "2.0",
					Release:    "12.cm2",
					Arch:       "noarch",
					SrcName:    "mariner-release",
					SrcVersion: "2.0",
					SrcRelease: "12.cm2",
				},
				{
					Name:       "filesystem",
					Version:    "1.1",
					Release:    "9.cm2",
					Arch:       "x86_64",
					SrcName:    "filesystem",
					SrcVersion: "1.1",
					SrcRelease: "9.cm2",
				},
				{
					Name:       "glibc",
					Version:    "2.35",
					Release:    "2.cm2",
					Arch:       "x86_64",
					SrcName:    "glibc",
					SrcVersion: "2.35",
					SrcRelease: "2.cm2",
				},
				{
					Name:       "ca-certificates-base",
					Version:    "3.0.0",
					Epoch:      1,
					Release:    "8.azl3",
					Arch:       "noarch",
					SrcName:    "ca-certificates",
					SrcEpoch:   1,
					SrcVersion: "3.0.0",
					SrcRelease: "8.azl3",
				},
			},
		},
		{
			name:    "sab path",
			content: "filesystem\t1.1-7.cm1\t1653164283\t1599428094",
			wantErr: "failed to parse a line (filesystem\t1.1-7.cm1\t1653164283\t1599428094)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := rpmqaPkgAnalyzer{}
			result, err := a.parseRpmqaManifest(strings.NewReader(test.content))
			if test.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, test.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantPkgs, result)
			}
		})
	}
}
