package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	azure2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_resolveFunc(t *testing.T) {

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "simple format call",
			expr:     "format('{0}/{1}', 'myPostgreSQLServer', 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name:     "simple format call with numbers",
			expr:     "format('{0} + {1} = {2}', 1, 2, 3)",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with nested format",
			expr:     "format('{0} + {1} = {2}', format('{0}', 1), 2, 3)",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with multiple nested format",
			expr:     "format('{0} + {1} = {2}', format('{0}', 1), 2, format('{0}', 3))",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with nested base64",
			expr:     "format('the base64 of \"hello, world\" is {0}', base64('hello, world'))",
			expected: "the base64 of \"hello, world\" is aGVsbG8sIHdvcmxk",
		},
		{
			name:     "dateTimeAdd with add a day",
			expr:     "dateTimeAdd(utcNow('yyyy-MM-dd'), 'P1D', 'yyyy-MM-dd')",
			expected: time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver{}

			resolvedValue, err := resolver.resolveExpressionString(tt.expr, types.NewTestMetadata())
			require.NoError(t, err)
			require.Equal(t, azure2.KindString, resolvedValue.Kind)

			require.Equal(t, tt.expected, resolvedValue.AsString())
		})
	}
}

func Test_resolveParameter(t *testing.T) {
	tests := []struct {
		name       string
		deployment *azure2.Deployment
		expr       string
		expected   string
	}{
		{
			name: "format call with parameter",
			deployment: &azure2.Deployment{
				Parameters: []azure2.Parameter{
					{
						Variable: azure2.Variable{
							Name:  "dbName",
							Value: azure2.NewValue("myPostgreSQLServer", types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "format('{0}/{1}', parameters('dbName'), 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver{
				deployment: tt.deployment,
			}

			resolvedValue, err := resolver.resolveExpressionString(tt.expr, types.NewTestMetadata())
			require.NoError(t, err)
			require.Equal(t, azure2.KindString, resolvedValue.Kind)

			require.Equal(t, tt.expected, resolvedValue.AsString())
		})
	}

}
