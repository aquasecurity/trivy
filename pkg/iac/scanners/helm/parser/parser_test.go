package parser_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
)

func Test_ParseFS(t *testing.T) {

	tests := []struct {
		name     string
		dir      string
		expected []string
	}{
		{
			name:     "source chart is located next to an same archived chart",
			dir:      "chart-and-archived-chart",
			expected: []string{"templates/pod.yaml"},
		},
		{
			name: "archive with symlinks",
			// shared-library in "charts" is symlink
			// ln -s ../shared-library charts/shared-library
			// helm package .
			dir:      "archive-with-symlinks",
			expected: []string{"charts/foo/templates/secret.yaml"},
		},
		{
			name: "chart with multiple archived deps",
			dir:  "multiple-archived-deps",
			expected: []string{
				"charts/wordpress-operator/templates/clusterrolebinding.yaml",
				"charts/wordpress-operator/templates/service.yaml",
				"charts/wordpress-operator/templates/deployment.yaml",
				"charts/wordpress-operator/templates/serviceaccount.yaml",
				"charts/wordpress-operator/templates/clusterrole.yaml",
				"charts/mysql-operator/templates/service_account_operator.yaml",
				"charts/mysql-operator/templates/cluster_role_operator.yaml",
				"charts/mysql-operator/templates/cluster_role_sidecar.yaml",
				"charts/mysql-operator/templates/cluster_role_binding_operator.yaml",
				"charts/mysql-operator/templates/service.yaml",
				"charts/mysql-operator/templates/deployment.yaml",
				"charts/mysql-operator/templates/cluster_kopf_keepering.yaml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parser.New()
			require.NoError(t, err)

			fsys := os.DirFS(filepath.Join("testdata", tt.dir))
			files, err := p.ParseFS(context.TODO(), fsys, ".")
			require.NoError(t, err)

			paths := lo.Map(files, func(f parser.ChartFile, _ int) string { return f.Path })
			assert.ElementsMatch(t, tt.expected, paths)
		})
	}
}
