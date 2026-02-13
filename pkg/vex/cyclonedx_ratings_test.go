package vex

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestParseOWASPRating(t *testing.T) {
	tests := []struct {
		name     string
		ratings  *[]cdx.VulnerabilityRating
		expected *types.OWASPRating
	}{
		{
			name:     "nil ratings",
			ratings:  nil,
			expected: nil,
		},
		{
			name:     "empty ratings",
			ratings:  &[]cdx.VulnerabilityRating{},
			expected: nil,
		},
		{
			name: "OWASP rating from vens",
			ratings: &[]cdx.VulnerabilityRating{
				{
					Method:   "OWASP",
					Score:    ptrFloat64(27.5),
					Severity: "medium",
					Vector:   "SL:7/M:7/O:7/S:7/ED:4/EE:4/A:4/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5",
				},
			},
			expected: &types.OWASPRating{
				Score:    27.5,
				Severity: "medium",
				Vector:   "SL:7/M:7/O:7/S:7/ED:4/EE:4/A:4/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5",
			},
		},
		{
			name: "multiple ratings - only OWASP extracted",
			ratings: &[]cdx.VulnerabilityRating{
				{
					Method:   "CVSSv3",
					Score:    ptrFloat64(7.5),
					Severity: "high",
				},
				{
					Method:   "OWASP",
					Score:    ptrFloat64(42.5),
					Severity: "high",
					Vector:   "SL:5/M:5/O:5/S:5/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7",
				},
				{
					Method:   "OTHER",
					Score:    ptrFloat64(10.0),
					Severity: "low",
				},
			},
			expected: &types.OWASPRating{
				Score:    42.5,
				Severity: "high",
				Vector:   "SL:5/M:5/O:5/S:5/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7",
			},
		},
		{
			name: "OWASP rating without score",
			ratings: &[]cdx.VulnerabilityRating{
				{
					Method:   "OWASP",
					Severity: "medium",
					Vector:   "SL:5/M:5/O:5/S:5/ED:5/EE:5/A:5/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5",
				},
			},
			expected: &types.OWASPRating{
				Score:    0,
				Severity: "medium",
				Vector:   "SL:5/M:5/O:5/S:5/ED:5/EE:5/A:5/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5",
			},
		},
		{
			name: "non-OWASP ratings only - returns nil",
			ratings: &[]cdx.VulnerabilityRating{
				{
					Method:   "CVSSv3",
					Score:    ptrFloat64(7.5),
					Severity: "high",
				},
				{
					Method:   "OTHER",
					Score:    ptrFloat64(10.0),
					Severity: "low",
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOWASPRating(tt.ratings)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func ptrFloat64(f float64) *float64 {
	return &f
}
