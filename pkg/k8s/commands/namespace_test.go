package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func Test_getNamespace(t *testing.T) {

	tests := []struct {
		name             string
		currentNamespace string
		opts             flag.Options
		want             string
	}{
		{
			name:             "--namespace=custom",
			currentNamespace: "default",
			opts: flag.Options{
				K8sOptions: flag.K8sOptions{
					Namespace: "custom",
				},
			},
			want: "custom",
		},
		{
			name:             "no namespaces passed",
			currentNamespace: "default",
			opts: flag.Options{
				K8sOptions: flag.K8sOptions{
					Namespace: "",
				},
			},
			want: "default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := getNamespace(test.opts, test.currentNamespace)
			assert.Equal(t, test.want, got)
		})
	}
}
