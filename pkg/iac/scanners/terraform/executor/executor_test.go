package executor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

var panicRule = scan.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc",
	Severity:  severity.High,
	CustomChecks: scan.CustomChecks{
		Terraform: &scan.TerraformCustomCheck{
			RequiredTypes:  []string{"resource"},
			RequiredLabels: []string{"problem"},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
				if resourceBlock.GetAttribute("panic").IsTrue() {
					panic("This is fine")
				}
				return
			},
		},
	},
}

func Test_PanicInCheckNotAllowed(t *testing.T) {

	reg := rules.Register(panicRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "problem" "this" {
	panic = true
}
`,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)

	results, err := New().Execute(modules)
	require.Error(t, err)

	assert.Empty(t, results.GetFailed())
}

func Test_PanicInCheckAllowed(t *testing.T) {

	reg := rules.Register(panicRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "problem" "this" {
	panic = true
}
`,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)

	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	_, err = New().Execute(modules)
	require.Error(t, err)
}

func Test_PanicNotInCheckNotIncludePassed(t *testing.T) {

	reg := rules.Register(panicRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "problem" "this" {
	panic = true
}
`,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)

	results, _ := New().Execute(modules)
	require.NoError(t, err)

	assert.Empty(t, results.GetFailed())
}

func Test_PanicNotInCheckNotIncludePassedStopOnError(t *testing.T) {

	reg := rules.Register(panicRule)
	defer rules.Deregister(reg)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "problem" "this" {
	panic = true
}
`,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)

	_, err = New().Execute(modules)
	require.Error(t, err)
}
