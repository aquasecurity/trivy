package terraform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/executor"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-policies/checks/cloud/aws/iam"
)

var badRule = scan.Rule{
	Provider:    providers.AWSProvider,
	Service:     "service",
	ShortCode:   "abc",
	Summary:     "A stupid example check for a test.",
	Impact:      "You will look stupid",
	Resolution:  "Don't do stupid stuff",
	Explanation: "Bad should not be set.",
	Severity:    severity.High,
	CustomChecks: scan.CustomChecks{
		Terraform: &scan.TerraformCustomCheck{
			RequiredTypes:  []string{"resource"},
			RequiredLabels: []string{"problem"},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
				if attr := resourceBlock.GetAttribute("bad"); attr.IsTrue() {
					results.Add("bad", attr)
				}
				return
			},
		},
	},
}

// IMPORTANT: if this test is failing, you probably need to set the version of go-cty in go.mod to the same version that hcl uses.
func Test_GoCtyCompatibilityIssue(t *testing.T) {
	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
data "aws_vpc" "default" {
  default = true
}

module "test" {
  source     = "../modules/problem/"
  cidr_block = data.aws_vpc.default.cidr_block
}
`,
		"/modules/problem/main.tf": `
variable "cidr_block" {}

variable "open" {                
  default = false
}                

resource "aws_security_group" "this" {
  name = "Test"                       

  ingress {    
    description = "HTTPs"
    from_port   = 443    
    to_port     = 443
    protocol    = "tcp"
    self        = ! var.open
    cidr_blocks = var.open ? [var.cidr_block] : null
  }                                                 
}  

resource "problem" "uhoh" {
	bad = true
}
`,
	})

	debug := bytes.NewBuffer([]byte{})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true), options.ParserWithDebug(debug))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, err := executor.New().Execute(modules)
	require.NoError(t, err)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")
	if t.Failed() {
		fmt.Println(debug.String())
	}
}

func Test_ProblemInModuleInSiblingDir(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
module "something" {
	source = "../modules/problem"
}
`,
		"modules/problem/main.tf": `
resource "problem" "uhoh" {
	bad = true
}
`},
	)

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInModuleIgnored(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"/project/main.tf": `
#tfsec:ignore:aws-service-abc
module "something" {
	source = "../modules/problem"
}
`,
		"modules/problem/main.tf": `
resource "problem" "uhoh" {
	bad = true
}
`},
	)

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleNotFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInModuleInSubdirectory(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
	source = "./modules/problem"
}
`,
		"project/modules/problem/main.tf": `
resource "problem" "uhoh" {
	bad = true
}
`})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInModuleInParentDir(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
	source = "../problem"
}
`,
		"problem/main.tf": `
resource "problem" "uhoh" {
	bad = true
}
`})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInModuleReuse(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something_good" {
	source = "../modules/problem"
	bad = false
}

module "something_bad" {
	source = "../modules/problem"
	bad = true
}
`,
		"modules/problem/main.tf": `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInNestedModule(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
	source = "../modules/a"
}
`,
		"modules/a/main.tf": `
	module "something" {
	source = "../../modules/b"
}
`,
		"modules/b/main.tf": `
module "something" {
	source = "../c"
}
`,
		"modules/c/main.tf": `
resource "problem" "uhoh" {
	bad = true
}
`,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true), options.ParserWithDebug(os.Stderr))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInReusedNestedModule(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
  source = "../modules/a"
  bad = false
}

module "something-bad" {
	source = "../modules/a"
	bad = true
}
`,
		"modules/a/main.tf": `
variable "bad" {
	default = false
}
module "something" {
	source = "../../modules/b"
	bad = var.bad
}
`,
		"modules/b/main.tf": `
variable "bad" {
	default = false
}
module "something" {
	source = "../c"
	bad = var.bad
}
`,
		"modules/c/main.tf": `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")
}

func Test_ProblemInInitialisedModule(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
  	source = "../modules/somewhere"
	bad = false
}
`,
		"modules/somewhere/main.tf": `
module "something_nested" {
	count = 1
  	source = "github.com/some/module.git"
	bad = true
}

variable "bad" {
	default = false
}

`,
		"project/.terraform/modules/something.something_nested/main.tf": `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`,
		"project/.terraform/modules/modules.json": `
	{"Modules":[
        {"Key":"something","Source":"../modules/somewhere","Version":"2.35.0","Dir":"../modules/somewhere"},
        {"Key":"something.something_nested","Source":"git::https://github.com/some/module.git","Version":"2.35.0","Dir":".terraform/modules/something.something_nested"}
    ]}
`,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")
}

func Test_ProblemInReusedInitialisedModule(t *testing.T) {

	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
  	source = "/nowhere"
	bad = false
} 
module "something2" {
	source = "/nowhere"
  	bad = true
}
`,
		"project/.terraform/modules/a/main.tf": `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`,
		"project/.terraform/modules/modules.json": `
	{"Modules":[{"Key":"something","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"},{"Key":"something2","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"}]}
`,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_ProblemInDuplicateModuleNameAndPath(t *testing.T) {
	registered := rules.Register(badRule)
	defer rules.Deregister(registered)

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
module "something" {
  source = "../modules/a"
  bad = 0
}

module "something-bad" {
	source = "../modules/a"
	bad = 1
}
`,
		"modules/a/main.tf": `
variable "bad" {
	default = 0
}
module "something" {
	source = "../b"
	bad = var.bad
}
`,
		"modules/b/main.tf": `
variable "bad" {
	default = 0
}
module "something" {
	source = "../c"
	bad = var.bad
}
`,
		"modules/c/main.tf": `
variable "bad" {
	default = 0
}
resource "problem" "uhoh" {
	count = var.bad
	bad = true
}
`,
	})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, badRule.LongID(), results, "")

}

func Test_Dynamic_Variables(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "something" "this" {

	dynamic "blah" {
		for_each = ["a"]

		content {
			ok = true
		}
	}
}
	
resource "bad" "thing" {
	secure = something.this.blah[0].ok
}
`})

	r1 := scan.Rule{
		Provider:  providers.AWSProvider,
		Service:   "service",
		ShortCode: "abc123",
		Severity:  severity.High,
		CustomChecks: scan.CustomChecks{
			Terraform: &scan.TerraformCustomCheck{
				RequiredLabels: []string{"bad"},
				Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
					if resourceBlock.GetAttribute("secure").IsTrue() {
						return
					}
					results.Add("example problem", resourceBlock)
					return
				},
			},
		},
	}
	reg := rules.Register(r1)
	defer rules.Deregister(reg)

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleFound(t, r1.LongID(), results, "")
}

func Test_Dynamic_Variables_FalsePositive(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `
resource "something" "else" {
	x = 1
	dynamic "blah" {
		for_each = toset(["true"])

		content {
			ok = each.value
		}
	}
}
	
resource "bad" "thing" {
	secure = something.else.blah.ok
}
`})

	r1 := scan.Rule{
		Provider:  providers.AWSProvider,
		Service:   "service",
		ShortCode: "abc123",
		Severity:  severity.High,
		CustomChecks: scan.CustomChecks{
			Terraform: &scan.TerraformCustomCheck{
				RequiredLabels: []string{"bad"},
				Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
					if resourceBlock.GetAttribute("secure").IsTrue() {
						return
					}
					results.Add("example problem", resourceBlock)
					return
				},
			},
		},
	}
	reg := rules.Register(r1)
	defer rules.Deregister(reg)

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleNotFound(t, r1.LongID(), results, "")
}

func Test_ReferencesPassedToNestedModule(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": `

resource "aws_iam_group" "developers" {
    name = "developers"
}

module "something" {
	source = "../modules/a"
    group = aws_iam_group.developers.name
}
`,
		"modules/a/main.tf": `
variable "group" {
    type = string
}

resource "aws_iam_group_policy" "mfa" {
  group = var.group
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  statement {
    sid    = "main"
    effect = "Allow"

    actions   = ["s3:*"]
    resources = ["*"]
    condition {
        test = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values = ["true"]
    }
  }
}
`})

	p := parser2.New(fs, "", parser2.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), "project")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	results, _, _ := executor.New().Execute(modules)
	testutil.AssertRuleNotFound(t, iam.CheckEnforceGroupMFA.LongID(), results, "")

}
