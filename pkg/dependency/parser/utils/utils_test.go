package utils

import (
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUniqueLibraries(t *testing.T) {
	tests := []struct {
		name     string
		libs     []types.Library
		wantLibs []types.Library
	}{
		{
			name: "happy path merge locations",
			libs: []types.Library{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Locations: []types.Location{
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
					Locations: []types.Location{
						{
							StartLine: 24,
							EndLine:   30,
						},
					},
				},
			},
			wantLibs: []types.Library{
				{
					ID:      "asn1@0.2.6",
					Name:    "asn1",
					Version: "0.2.6",
					Locations: []types.Location{
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
			libs: []types.Library{
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
			wantLibs: []types.Library{
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
			libs: []types.Library{
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
			wantLibs: []types.Library{
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
			gotLibs := UniqueLibraries(tt.libs)
			require.Equal(t, tt.wantLibs, gotLibs)
		})
	}
}
