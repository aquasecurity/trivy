package vars_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestLoader_Load(t *testing.T) {
	files := map[string]string{
		"host_vars/host1.yaml": `
var1: value1
var2: value2
`,
		"host_vars/host2.yaml": `
var1: value1
var2: value2
`,
		"group_vars/group1.yaml": `
group_var1: gvalue1
`,
		"group_vars/group1/vars.yaml": `
group_var1: gvalue1_1
`,
		"group_vars/group1/vars2.yaml": `
group_var1: gvalue1_2
`,
		"group_vars/all": `
all_var: allvalue
`,
	}

	fsys := testutil.CreateFS(t, files)
	rootSrc := fsutils.NewFileSource(fsys, ".")
	sources := vars.PlaybookVarsSources(rootSrc)
	sources = append(sources, vars.InventoryVarsSources(rootSrc.Join("inventory"))...)
	got := vars.LoadVars(sources)

	expected := vars.LoadedVars{
		vars.ScopeHost: map[string]vars.Vars{
			"host1": {
				"var1": "value1",
				"var2": "value2",
			},
			"host2": {
				"var1": "value1",
				"var2": "value2",
			},
		},
		vars.ScopeGroupAll: map[string]vars.Vars{
			"all": {
				"all_var": "allvalue",
			},
		},
		vars.ScopeGroupSpecific: map[string]vars.Vars{
			"group1": {
				"group_var1": "gvalue1_2",
			},
		},
	}

	assert.Equal(t, expected, got)
}
