package utils

import (
	"testing"

	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestUniqueLibraries(t *testing.T) {
	tests := []struct {
		name     string
		pkgs     []ftypes.Package
		wantPkgs []ftypes.Package
	}{
		{
			name: "happy path merge locations",
			pkgs: []ftypes.Package{
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
			wantPkgs: []ftypes.Package{
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
			pkgs: []ftypes.Package{
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
			wantPkgs: []ftypes.Package{
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
			pkgs: []ftypes.Package{
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
			wantPkgs: []ftypes.Package{
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
			gotPkgs := UniquePackages(tt.pkgs)
			require.Equal(t, tt.wantPkgs, gotPkgs)
		})
	}
}
