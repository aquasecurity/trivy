package utils

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUniqueLibraries(t *testing.T) {
	tests := []struct {
		name     string
		libs     []ftypes.Package
		wantLibs []ftypes.Package
	}{
		{
			name: "happy path merge locations",
			libs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Locations: []ftypes.Location{
						{
							StartLine: 10,
							EndLine:   14,
						},
					},
				},
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Locations: []ftypes.Location{
						{
							StartLine: 24,
							EndLine:   30,
						},
					},
				},
			},
			wantLibs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Locations: []ftypes.Location{
						{
							StartLine: 10,
							EndLine:   14,
						},
						{
							StartLine: 24,
							EndLine:   30,
						},
					},
				},
			},
		},
		{
			name: "happy path Dev and Root deps",
			libs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     true,
				},
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     false,
				},
			},
			wantLibs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     false,
				},
			},
		},
		{
			name: "happy path Root and Dev deps",
			libs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     false,
				},
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     true,
				},
			},
			wantLibs: []ftypes.Package{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Dev:     false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLibs := UniquePackages(tt.libs)
			require.Equal(t, tt.wantLibs, gotLibs)
		})
	}
}
