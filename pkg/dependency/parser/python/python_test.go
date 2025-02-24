package python_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
)

func Test_NormalizePkgName(t *testing.T) {
	tests := []struct {
		pkgName  string
		expected string
	}{
		{
			pkgName:  "SecretStorage",
			expected: "secretstorage",
		},
		{
			pkgName:  "pywin32-ctypes",
			expected: "pywin32-ctypes",
		},
		{
			pkgName:  "jaraco.classes",
			expected: "jaraco-classes",
		},
		{
			pkgName:  "green_gdk",
			expected: "green-gdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			assert.Equal(t, tt.expected, python.NormalizePkgName(tt.pkgName))
		})
	}
}
