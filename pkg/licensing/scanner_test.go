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
			name: "has plus",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.BSD3Clause,
					expression.Apache20,
				},
			},
			licenseName:  "Apache-2.0+",
			wantCategory: types.CategoryForbidden,
			wantSeverity: "CRITICAL",
		},
		{
			name: "`categories` contains license with suffix",
			categories: map[types.LicenseCategory][]string{
				types.CategoryNotice: {
					"LGPL-2.0-only",
				},
			},
			licenseName:  "LGPL-2.0-only",
			wantCategory: types.CategoryNotice,
			wantSeverity: "LOW",
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
			name: "unnormalized license",
			categories: map[types.LicenseCategory][]string{
				types.CategoryRestricted: {
					expression.BSD3Clause,
					expression.MIT,
				},
			},
			licenseName:  "MIT License",
			wantCategory: types.CategoryRestricted,
			wantSeverity: "HIGH",
		},
		{
			name: "compound OR license",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.GPL30,
				},
				types.CategoryRestricted: {
					expression.Apache20,
				},
			},
			licenseName:  expression.GPL30 + " OR " + expression.Apache20,
			wantCategory: types.CategoryRestricted,
			wantSeverity: "HIGH",
		},
		{
			name: "compound AND license",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.GPL30,
				},
				types.CategoryRestricted: {
					expression.Apache20,
				},
			},
			licenseName:  expression.GPL30 + " AND " + expression.Apache20,
			wantCategory: types.CategoryForbidden,
			wantSeverity: "CRITICAL",
		},
		{
			name: "compound unknown license",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.GPL30,
				},
			},
			licenseName:  expression.GPL30 + " AND " + expression.Apache20,
			wantCategory: types.CategoryUnknown,
			wantSeverity: "UNKNOWN",
		},
		{
			name: "compound long license, recursive",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {
					expression.GPL30,
				},
				types.CategoryRestricted: {
					expression.BSD3Clause,
				},
				types.CategoryNotice: {
					expression.Apache20,
				},
			},
			licenseName:  "(" + expression.BSD3Clause + " OR " + expression.GPL30 + ")" + " AND (" + expression.GPL30 + " OR " + expression.Apache20 + ")",
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
		{
			// `Unlicensed` is a special license name in npm.
			// It means the developer does not grant anyone the right to use the private or unpublished package under any circumstances.
			name: "'unlicensed' npm license as unknown",
			categories: map[types.LicenseCategory][]string{
				types.CategoryUnencumbered: {
					expression.Unlicense,
				},
			},
			licenseName:  "UNLICENSED",
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

func TestScanner_ScanTextLicense(t *testing.T) {
	tests := []struct {
		name         string
		categories   map[types.LicenseCategory][]string
		licenseText  string
		wantCategory types.LicenseCategory
		wantSeverity string
	}{
		{
			name: "match license text pattern",
			categories: map[types.LicenseCategory][]string{
				types.CategoryForbidden: {"text://Apache.*License"},
			},
			licenseText:  "Apache Software Foundation License",
			wantCategory: types.CategoryForbidden,
			wantSeverity: "CRITICAL",
		},
		{
			name: "no match returns unknown",
			categories: map[types.LicenseCategory][]string{
				types.CategoryNotice: {"text://MIT.*"},
			},
			licenseText:  "Some other license text",
			wantCategory: types.CategoryUnknown,
			wantSeverity: "UNKNOWN",
		},
		{
			name: "invalid regexp is ignored",
			categories: map[types.LicenseCategory][]string{
				types.CategoryRestricted: {"text://("},
			},
			licenseText:  "MIT License",
			wantCategory: types.CategoryUnknown,
			wantSeverity: "UNKNOWN",
		},
		{
			name: "category without text prefix is ignored",
			categories: map[types.LicenseCategory][]string{
				types.CategoryNotice: {"MIT"},
			},
			licenseText:  "MIT License",
			wantCategory: types.CategoryUnknown,
			wantSeverity: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := licensing.NewScanner(tt.categories)
			gotCategory, gotSeverity := s.ScanTextLicense(tt.licenseText)
			assert.Equal(t, tt.wantCategory, gotCategory)
			assert.Equal(t, tt.wantSeverity, gotSeverity)
		})
	}
}
