package spec_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name        string
		specPath    string
		expectError bool
	}{
		{name: "spec with valid scanner", specPath: "./testdata/spec.yaml", expectError: false},
		{name: "spec with non valid scanner", specPath: "./testdata/bad_scanner_spec.yaml", expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadSpecFile(tt.specPath)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func ReadSpecFile(specFilePath string) (*spec.ComplianceSpec, error) {
	b, err := os.ReadFile(specFilePath)
	if err != nil {
		return nil, err
	}
	cr := spec.ComplianceSpec{}
	err = yaml.Unmarshal(b, &cr)
	if err != nil {
		return nil, err
	}
	return &cr, nil
}
