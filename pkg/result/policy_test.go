package result

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalPolicyStore(t *testing.T) {
	policyFiles := map[string][]byte{
		"good.rego": []byte(`
package trivy

default ignore = false

focused_packages := {"org.apache.logging.log4j:log4j-core"}

ignore_severities := {"LOW", "MEDIUM"}

ignore {
    input.PkgName != focused_packages[_]
}
`),
		"bad.rego": []byte(`
package trivy

invalid rego file
`),
	}
	tempDir := t.TempDir()
	for filename, content := range policyFiles {
		err := os.WriteFile(filepath.Join(tempDir, filename), content, 0600)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		policyFile    string
		expectedError string
	}{
		{
			name:          "Good rego file",
			policyFile:    filepath.Join(tempDir, "good.rego"),
			expectedError: "",
		},
		{
			name:          "Bad rego file",
			policyFile:    filepath.Join(tempDir, "bad.rego"),
			expectedError: "unable to prepare for eval: ",
		},
		{
			name:          "Non-existing rego file",
			policyFile:    filepath.Join(tempDir, "non-existing.rego"),
			expectedError: "unable to read policy file ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLocalPolicyStore(context.Background(), tt.policyFile)
			if tt.expectedError != "" {
				assert.ErrorContains(t, err, tt.expectedError, tt.name)
			} else {
				assert.Nil(t, err, tt.expectedError, tt.name)
			}
		})
	}
}
