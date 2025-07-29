package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestNewRegoFilter(t *testing.T) {
	tests := []struct {
		name    string
		opts    flag.K8sOptions
		wantNil bool
		wantErr bool
	}{
		{
			name:    "no policy specified",
			opts:    flag.K8sOptions{},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid policy file",
			opts: flag.K8sOptions{
				K8sSkipPolicy: "testdata/valid-policy.rego",
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "invalid policy file path",
			opts: flag.K8sOptions{
				K8sSkipPolicy: "nonexistent.rego",
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test policy file if needed
			if tt.opts.K8sSkipPolicy == "testdata/valid-policy.rego" {
				createTestPolicy(t, tt.opts.K8sSkipPolicy)
			}

			filter, err := NewRegoFilter(t.Context(), tt.opts)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantNil {
				assert.Nil(t, filter)
			} else if !tt.wantErr {
				assert.NotNil(t, filter)
			}
		})
	}
}

func TestRegoFilter_ShouldIgnore(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		artifact   K8sArtifact
		wantIgnore bool
		wantErr    bool
	}{
		{
			name: "ignore deployments with zero replicas",
			policy: `
package trivy.kubernetes

ignore {
	input.kind == "Deployment"
	input.spec.replicas == 0
}
`,
			artifact: K8sArtifact{
				Kind:      "Deployment",
				Namespace: "default",
				Name:      "test-app",
				Spec: map[string]any{
					"replicas": 0,
				},
			},
			wantIgnore: true,
			wantErr:    false,
		},
		{
			name: "don't ignore deployments with replicas > 0",
			policy: `
package trivy.kubernetes

ignore {
	input.kind == "Deployment"
	input.spec.replicas == 0
}
`,
			artifact: K8sArtifact{
				Kind:      "Deployment",
				Namespace: "default",
				Name:      "test-app",
				Spec: map[string]any{
					"replicas": 3,
				},
			},
			wantIgnore: false,
			wantErr:    false,
		},
		{
			name: "ignore pods with specific labels",
			policy: `
package trivy.kubernetes

ignore {
	input.kind == "Pod"
	input.labels["environment"] == "test"
}
`,
			artifact: K8sArtifact{
				Kind:      "Pod",
				Namespace: "default",
				Name:      "test-pod",
				Labels: map[string]string{
					"environment": "test",
				},
			},
			wantIgnore: true,
			wantErr:    false,
		},
		{
			name: "ignore resources in specific namespace",
			policy: `
package trivy.kubernetes

ignore {
	input.namespace == "kube-system"
}
`,
			artifact: K8sArtifact{
				Kind:      "Pod",
				Namespace: "kube-system",
				Name:      "system-pod",
			},
			wantIgnore: true,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary policy file
			tmpFile, err := os.CreateTemp(t.TempDir(), "test-policy-*.rego")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.policy)
			require.NoError(t, err)
			tmpFile.Close()

			opts := flag.K8sOptions{
				K8sSkipPolicy: tmpFile.Name(),
			}

			filter, err := NewRegoFilter(t.Context(), opts)
			require.NoError(t, err)
			require.NotNil(t, filter)

			ignore, err := filter.ShouldIgnore(t.Context(), tt.artifact)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantIgnore, ignore)
			}
		})
	}
}

func TestRegoFilter_ShouldIgnore_NilFilter(t *testing.T) {
	var filter *RegoFilter = nil
	artifact := K8sArtifact{
		Kind:      "Pod",
		Namespace: "default",
		Name:      "test-pod",
	}

	ignore, err := filter.ShouldIgnore(t.Context(), artifact)
	require.NoError(t, err)
	assert.False(t, ignore)
}

func TestConvertToK8sArtifact(t *testing.T) {
	tests := []struct {
		name         string
		kind         string
		namespace    string
		resourceName string
		labels       map[string]string
		annotations  map[string]string
		spec         any
		want         K8sArtifact
	}{
		{
			name:         "basic conversion with nil maps",
			kind:         "Pod",
			namespace:    "default",
			resourceName: "test-pod",
			labels:       nil,
			annotations:  nil,
			spec:         nil,
			want: K8sArtifact{
				Kind:        "Pod",
				Namespace:   "default",
				Name:        "test-pod",
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
				Spec:        nil,
			},
		},
		{
			name:         "conversion with labels and annotations",
			kind:         "Deployment",
			namespace:    "production",
			resourceName: "app-deployment",
			labels:       map[string]string{"app": "web", "version": "v1"},
			annotations:  map[string]string{"deployment.kubernetes.io/revision": "1"},
			spec:         map[string]any{"replicas": 3},
			want: K8sArtifact{
				Kind:        "Deployment",
				Namespace:   "production",
				Name:        "app-deployment",
				Labels:      map[string]string{"app": "web", "version": "v1"},
				Annotations: map[string]string{"deployment.kubernetes.io/revision": "1"},
				Spec:        map[string]any{"replicas": 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertToK8sArtifact(tt.kind, tt.namespace, tt.resourceName, tt.labels, tt.annotations, tt.spec)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Helper function to create test policy file
func createTestPolicy(t *testing.T, policyPath string) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(policyPath), 0o755)
	require.NoError(t, err)

	policy := `
package trivy.kubernetes

ignore {
	input.kind == "Deployment"
	input.spec.replicas == 0
}
`
	err = os.WriteFile(policyPath, []byte(policy), 0o644)
	require.NoError(t, err)

	t.Cleanup(func() {
		os.RemoveAll(filepath.Dir(policyPath))
	})
}
