package vars_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestXxx(t *testing.T) {
	files := map[string]string{
		"host_vars/host1.yaml":             "",
		"group_vars/group1.yaml":           "",
		"group_vars/all":                   "",
		"inventory/host_vars/host1.yaml":   "",
		"inventory/group_vars/group1.yaml": "",
	}
	fsys := testutil.CreateFS(t, files)
	loader := vars.VarsLoader{}
	sources := vars.PlaybookVarsSources(fsys, ".")
	sources = append(sources, vars.InventoryVarsSources(fsys, "inventory")...)
	vars := loader.Load(sources)
	assert.Len(t, vars, 5)
}
