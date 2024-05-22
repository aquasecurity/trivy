package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestScanner_Scan(t *testing.T) {
	tests := []struct {
		name         string
		categories   map[types.LicenseCategory][]string
		licenseName  string
		wantCategory types.LicenseCategory
		wantSeverity string
	}{
		{
			name: "forbidden",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					licensing.BSD3Clause,
					licensing.Apache20,
				},
			},
			licenseName:  licensing.Apache20,
			wantCategory: types.CategoryForbidden,
			wantSeverity: "CRITICAL",
		},
		{
			name: "restricted",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					licensing.GPL30,
				},
				types.CategoryRestricted: {
					licensing.BSD3Clause,
					licensing.Apache20,
				},
			},
			licenseName:  licensing.BSD3Clause,
			wantCategory: types.CategoryRestricted,
			wantSeverity: "HIGH",
		},
		{
			name:         "unknown",
			categories:   map[types.LicenseCategory][]string{},
			licenseName:  licensing.BSD3Clause,
			wantCategory: types.CategoryUnknown,
			wantSeverity: "UNKNOWN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := licensing.NewScanner(tt.categories)
			gotCategory, gotSeverity := s.Scan(tt.licenseName)
			assert.Equalf(t, tt.wantCategory, gotCategory, "Scan(%v)", tt.licenseName)
			assert.Equalf(t, tt.wantSeverity, gotSeverity, "Scan(%v)", tt.licenseName)
		})
	}
}
