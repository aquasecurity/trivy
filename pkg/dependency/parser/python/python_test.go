package python_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
)

func Test_NormalizePkgName(t *testing.T) {
	tests := []struct {
		pkgName   string
		lowerCase bool
		expected  string
	}{
		{
			pkgName:   "SecretStorage",
			lowerCase: true,
			expected:  "secretstorage",
		},
		{
			pkgName:   "SecretStorage",
			lowerCase: false,
			expected:  "SecretStorage",
		},
		{
			pkgName:   "pywin32-ctypes",
			lowerCase: true,
			expected:  "pywin32-ctypes",
		},
		{
			pkgName:   "jaraco.classes",
			lowerCase: true,
			expected:  "jaraco-classes",
		},
		{
			pkgName:   "green_gdk",
			lowerCase: true,
			expected:  "green-gdk",
		},
		{
			pkgName:   "foo--bar__baz",
			lowerCase: true,
			expected:  "foo-bar-baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			assert.Equal(t, tt.expected, python.NormalizePkgName(tt.pkgName, tt.lowerCase))
		})
	}
}
