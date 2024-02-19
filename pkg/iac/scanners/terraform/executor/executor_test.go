package executor

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := New().Execute(modules)
	assert.Equal(t, len(results.GetFailed()), 0)
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

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	_, _, err = New(OptionStopOnErrors(false)).Execute(modules)
	assert.Error(t, err)
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

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := New().Execute(modules)
	assert.Equal(t, len(results.GetFailed()), 0)
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

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)

	_, _, err = New(OptionStopOnErrors(false)).Execute(modules)
	assert.Error(t, err)
}
