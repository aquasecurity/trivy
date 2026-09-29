package rego_test

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func TestTrivyVersionFilter(t *testing.T) {
	module := &ast.Module{Package: &ast.Package{Location: ast.NewLocation(nil, "/test.rego", 1, 1)}}

	tests := []struct {
		name       string
		trivyVer   string
		minVersion string
		expected   bool
	}{
		{"no minimum version", "0.1.0", "", true},
		{"compatible version", "0.20.0", "0.19.0", true},
		{"incompatible version", "0.18.0", "0.19.0", false},
		{"invalid min version", "0.20.0", "invalid", false},
		{"invalid trivy version", "invalid", "0.19.0", true},
		{"empty trivy version", "", "0.19.0", true},
		{"dev trivy version", "dev", "0.19.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := rego.TrivyVersionFilter(tt.trivyVer)
			metadata := &rego.StaticMetadata{
				MinimumTrivyVersion: tt.minVersion,
			}
			result := filter(module, metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFrameworksFilter(t *testing.T) {
	module := &ast.Module{}

	tests := []struct {
		name     string
		moduleFw map[framework.Framework][]string
		filterFw []framework.Framework
		expected bool
	}{
		{
			name: "match single",
			moduleFw: map[framework.Framework][]string{
				framework.CIS_AWS_1_2: {"2.5"},
			},
			filterFw: []framework.Framework{framework.CIS_AWS_1_2},
			expected: true,
		},
		{
			name: "match one of many",
			moduleFw: map[framework.Framework][]string{
				framework.CIS_AWS_1_2: {"2.5"},
				framework.CIS_AWS_1_4: {"4.5"},
			},
			filterFw: []framework.Framework{framework.CIS_AWS_1_2},
			expected: true,
		},
		{
			name: "no match",
			moduleFw: map[framework.Framework][]string{
				framework.CIS_AWS_1_2: {"2.5"},
			},
			filterFw: []framework.Framework{"PCI"},
			expected: false,
		},
		{
			name: "empty filter",
			moduleFw: map[framework.Framework][]string{
				framework.CIS_AWS_1_2: {"2.5"},
			},
			filterFw: nil,
			expected: false,
		},
		{
			name: "has default framework and empty filter",
			moduleFw: map[framework.Framework][]string{
				framework.Default:     {},
				framework.CIS_AWS_1_2: {"2.5"},
			},
			filterFw: nil,
			expected: true,
		},
		{
			name:     "empty module frameworks",
			moduleFw: nil,
			filterFw: []framework.Framework{framework.Default},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &rego.StaticMetadata{
				Frameworks: tt.moduleFw,
			}
			filter := rego.FrameworksFilter(tt.filterFw)
			result := filter(module, metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIncludeDeprecatedFilter(t *testing.T) {
	module := &ast.Module{}

	tests := []struct {
		name       string
		include    bool
		deprecated bool
		expected   bool
	}{
		{"include false, not deprecated", false, false, true},
		{"include false, deprecated", false, true, false},
		{"include true, deprecated", true, true, true},
		{"include true, not deprecated", true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &rego.StaticMetadata{Deprecated: tt.deprecated}
			filter := rego.IncludeDeprecatedFilter(tt.include)
			result := filter(module, metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}
