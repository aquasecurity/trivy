package commands

import (
	"testing"

	"gotest.tools/assert"
)

func Test_extractKindAndName(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedKind  string
		expectedName  string
		expectedError string
	}{
		{
			name:         "one argument only",
			args:         []string{"deploy"},
			expectedKind: "deploy",
			expectedName: "",
		},
		{
			name:         "one argument only, multiple targets",
			args:         []string{"deploy,configmaps"},
			expectedKind: "deploy,configmaps",
			expectedName: "",
		},
		{
			name:         "bar separated",
			args:         []string{"deploy/orion"},
			expectedKind: "deploy",
			expectedName: "orion",
		},
		{
			name:         "space separated",
			args:         []string{"deploy", "lua"},
			expectedKind: "deploy",
			expectedName: "lua",
		},
		{
			name:          "multiple arguments separated",
			args:          []string{"test", "test", "test"},
			expectedError: "can't parse arguments [test test test]. Please run `trivy k8s` for usage.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, name, err := extractKindAndName(test.args)

			if len(test.expectedError) > 0 {
				assert.Error(t, err, test.expectedError)
				return
			}

			assert.Equal(t, test.expectedKind, kind)
			assert.Equal(t, test.expectedName, name)
		})
	}
}
