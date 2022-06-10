package commands

import (
	"testing"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"gotest.tools/assert"
)

func Test_getNamespace(t *testing.T) {

	tests := []struct {
		name             string
		currentNamespace string
		opt              cmd.Option
		expected         string
	}{
		{
			name:             "--namespace=custom",
			currentNamespace: "default",
			opt:              cmd.Option{KubernetesOption: option.KubernetesOption{Namespace: "custom"}},
			expected:         "custom",
		},
		{
			name:             "no namespaces passed",
			currentNamespace: "default",
			opt:              cmd.Option{KubernetesOption: option.KubernetesOption{Namespace: ""}},
			expected:         "default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := getNamespace(test.opt, test.currentNamespace)
			assert.Equal(t, test.expected, got)
		})
	}
}
