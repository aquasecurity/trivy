package ansible

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func TestBasicScan(t *testing.T) {
	fsys := fstest.MapFS{
		"playbook.yaml": {
			Data: []byte(`---
- name: Update web servers
  hosts: localhost

  tasks:
  - name: Ensure apache is at the latest version
    s3_bucket:
      name: mys3bucket
      public_access:
`),
		},
	}

	scanner := New(
		rego.WithEmbeddedLibraries(true),
		rego.WithEmbeddedPolicies(true),
	)

	results, err := scanner.ScanFS(t.Context(), fsys, ".")
	require.NoError(t, err)

	failed := results.GetFailed()
	assert.NotEmpty(t, failed)
}
