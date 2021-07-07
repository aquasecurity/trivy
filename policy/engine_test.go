package policy_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/fanal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestLoad(t *testing.T) {
	type args struct {
		policyPaths []string
		dataPaths   []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "happy path",
			args: args{
				policyPaths: []string{"testdata/happy"},
				dataPaths:   []string{"testdata/data"},
			},
		},
		{
			name: "broken policy",
			args: args{
				policyPaths: []string{"testdata/sad/broken_rule.rego"},
				dataPaths:   []string{"testdata/data"},
			},
			wantErr: "var msg is unsafe",
		},
		{
			name: "no policies",
			args: args{
				policyPaths: []string{"testdata/data/"},
			},
			wantErr: "no policies found in [testdata/data/]",
		},
		{
			name: "non-existent policy path",
			args: args{
				policyPaths: []string{"testdata/non-existent/"},
			},
			wantErr: "no such file or directory",
		},
		{
			name: "non-existent data path",
			args: args{
				policyPaths: []string{"testdata/happy"},
				dataPaths:   []string{"testdata/non-existent/"},
			},
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := policy.Load(tt.args.policyPaths, tt.args.dataPaths)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestEngine_Check(t *testing.T) {
	type args struct {
		configs    []types.Config
		namespaces []string
	}
	tests := []struct {
		name        string
		policyPaths []string
		dataPaths   []string
		args        args
		want        []types.Misconfiguration
		wantErr     string
	}{
		{
			name:        "happy path",
			policyPaths: []string{"testdata/happy"},
			dataPaths:   []string{"testdata/data"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Successes: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_300",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-300",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Pod",
								Severity: "CRITICAL",
							},
						},
					},
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny test",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "XYZ-100",
								Type:               "Kubernetes Security Check",
								Title:              "Bad Deployment",
								Severity:           "HIGH",
								Description:        "Something bad",
								RecommendedActions: "Do something great",
								References:         []string{"http://example.com"},
							},
						},
					},
				},
			},
		},
		{
			name:        "multiple deny",
			policyPaths: []string{"testdata/multiple_deny"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny test",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Something Bad",
								Severity: "LOW",
							},
						},
					},
				},
			},
		},
		{
			name:        "combined files",
			policyPaths: []string{"testdata/combine"},
			dataPaths:   []string{"testdata/data"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment1.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test1",
							},
						},
					},
					{
						Type:     types.Kubernetes,
						FilePath: "deployment2.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test2",
							},
						},
					},
				},
				namespaces: []string{"dummy", "testdata"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment1.yaml",
					Successes: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_400",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-400",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Pod",
								Severity: "LOW",
							},
						},
					},
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny combined test1",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Deployment",
								Severity: "HIGH",
							},
						},
					},
					Warnings: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_200",
							Message:   "deny test1",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-200",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "MEDIUM",
							},
						},
					},
				},
				{
					FileType: types.Kubernetes,
					FilePath: "deployment2.yaml",
					Successes: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_400",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-400",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Pod",
								Severity: "LOW",
							},
						},
					},
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny combined test2",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Deployment",
								Severity: "HIGH",
							},
						},
					},
					Warnings: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_200",
							Message:   "deny test2",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-200",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:        "sub configs",
			policyPaths: []string{"testdata/happy"},
			dataPaths:   []string{"testdata/data"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test1",
							},
						},
					},
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test2",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Successes: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_300",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-300",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Pod",
								Severity: "CRITICAL",
							},
						},
					},
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny test1",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "XYZ-100",
								Type:               "Kubernetes Security Check",
								Title:              "Bad Deployment",
								Severity:           "HIGH",
								Description:        "Something bad",
								RecommendedActions: "Do something great",
								References:         []string{"http://example.com"},
							},
						},
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny test2",
							PolicyMetadata: types.PolicyMetadata{
								ID:                 "XYZ-100",
								Type:               "Kubernetes Security Check",
								Title:              "Bad Deployment",
								Severity:           "HIGH",
								Description:        "Something bad",
								RecommendedActions: "Do something great",
								References:         []string{"http://example.com"},
							},
						},
					},
				},
			},
		},
		{
			name:        "namespace exception",
			policyPaths: []string{"testdata/namespace_exception"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_200",
							Message:   "deny 200 test",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-200",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "HIGH",
							},
						},
					},
					Exceptions: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_100",
							Message:   `data.namespace.exceptions.exception[_] == "testdata.kubernetes.xyz_100"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:        "namespace exception with combined files",
			policyPaths: []string{"testdata/combine_exception"},
			dataPaths:   []string{"testdata/data"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment1.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test1",
							},
						},
					},
					{
						Type:     types.Kubernetes,
						FilePath: "deployment2.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test2",
							},
						},
					},
				},
				namespaces: []string{"dummy", "testdata"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment1.yaml",
					Warnings: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny combined test1",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Deployment",
								Severity: "HIGH",
							},
						},
						{
							Namespace: "testdata.xyz_200",
							Message:   "deny test1",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-200",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "MEDIUM",
							},
						},
					},
					Exceptions: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_300",
							Message:   `data.namespace.exceptions.exception[_] == "testdata.xyz_300"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-300",
								Type:     "Kubernetes Security Check",
								Title:    "Always Fail",
								Severity: "LOW",
							},
						},
					},
				},
				{
					FileType: types.Kubernetes,
					FilePath: "deployment2.yaml",
					Warnings: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_100",
							Message:   "deny combined test2",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Combined Deployment",
								Severity: "HIGH",
							},
						},
						{
							Namespace: "testdata.xyz_200",
							Message:   "deny test2",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-200",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "MEDIUM",
							},
						},
					},
					Exceptions: []types.MisconfResult{
						{
							Namespace: "testdata.xyz_300",
							Message:   `data.namespace.exceptions.exception[_] == "testdata.xyz_300"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-300",
								Type:     "Kubernetes Security Check",
								Title:    "Always Fail",
								Severity: "LOW",
							},
						},
					},
				},
			},
		},
		{
			name:        "rule exception",
			policyPaths: []string{"testdata/rule_exception"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_100",
							Message:   "deny bar test",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "HIGH",
							},
						},
					},
					Exceptions: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_100",
							Message:   `data.testdata.kubernetes.xyz_100.exception[_][_] == "foo"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "XYZ-100",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:        "missing id and severity",
			policyPaths: []string{"testdata/sad/missing_metadata_fields.rego"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_100",
							Message:   "deny test",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "N/A",
								Type:     "Kubernetes Security Check",
								Title:    "Bad Deployment",
								Severity: "UNKNOWN",
							},
						},
					},
				},
			},
		},
		{
			name:        "missing __rego_metadata__",
			policyPaths: []string{"testdata/sad/missing_metadata.rego"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test",
							},
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			want: []types.Misconfiguration{
				{
					FileType: types.Kubernetes,
					FilePath: "deployment.yaml",
					Failures: []types.MisconfResult{
						{
							Namespace: "testdata.kubernetes.xyz_100",
							Message:   "deny test",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "N/A",
								Type:     "N/A",
								Title:    "N/A",
								Severity: "UNKNOWN",
							},
						},
					},
				},
			},
		},
		{
			name:        "missing filepath",
			policyPaths: []string{"testdata/sad/missing_filepath.rego"},
			dataPaths:   []string{"testdata/data"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment1.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]interface{}{
								"name": "test1",
							},
						},
					},
				},
				namespaces: []string{"dummy", "testdata"},
			},
			wantErr: `rule missing 'filepath' field`,
		},
		{
			name:        "broken __rego_metadata__",
			policyPaths: []string{"testdata/sad/broken_metadata.rego"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			wantErr: "'__rego_metadata__' must be map",
		},
		{
			name:        "broken msg",
			policyPaths: []string{"testdata/sad/broken_msg.rego"},
			args: args{
				configs: []types.Config{
					{
						Type:     types.Kubernetes,
						FilePath: "deployment.yaml",
						Content: map[string]interface{}{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
						},
					},
				},
				namespaces: []string{"testdata", "dummy"},
			},
			wantErr: "rule missing 'msg' field",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := policy.Load(tt.policyPaths, tt.dataPaths)
			require.NoError(t, err)

			got, err := engine.Check(context.Background(), tt.args.configs, tt.args.namespaces)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
