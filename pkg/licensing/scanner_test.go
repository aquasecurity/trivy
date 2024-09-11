package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
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
					expression.BSD3Clause,
					expression.Apache20,
				},
			},
			licenseName:  expression.Apache20,
			wantCategory: types.CategoryForbidden,
			wantSeverity: "CRITICAL",
		},
		{
			name: "restricted",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.GPL30,
				},
				types.CategoryRestricted: {
					expression.BSD3Clause,
					expression.Apache20,
				},
			},
			licenseName:  expression.BSD3Clause,
			wantCategory: types.CategoryRestricted,
			wantSeverity: "HIGH",
		},
		{
			name:         "unknown",
			categories:   make(map[types.LicenseCategory][]string),
			licenseName:  expression.BSD3Clause,
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
