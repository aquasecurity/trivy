package parser

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func Test_BasicParsing(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"test.tf": `

locals {
	proxy = var.cats_mother
}

variable "cats_mother" {
	default = "boots"
}

provider "cats" {

}

moved {

}

import {
  to = cats_cat.mittens
  id = "mittens"
}

resource "cats_cat" "mittens" {
	name = "mittens"
	special = true
}

resource "cats_kitten" "the-great-destroyer" {
	name = "the great destroyer"
	parent = cats_cat.mittens.name
}

data "cats_cat" "the-cats-mother" {
	name = local.proxy
}

check "cats_mittens_is_special" {
  data "cats_cat" "mittens" {
    name = "mittens"
  }

  assert {
    condition = data.cats_cat.mittens.special == true
    error_message = "${data.cats_cat.mittens.name} must be special"
  }
}

`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))
	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)

	blocks := modules[0].GetBlocks()

	// variable
	variables := blocks.OfType("variable")
	require.Len(t, variables, 1)
	assert.Equal(t, "variable", variables[0].Type())
	require.Len(t, variables[0].Labels(), 1)
	assert.Equal(t, "cats_mother", variables[0].TypeLabel())
	defaultVal := variables[0].GetAttribute("default")
	require.NotNil(t, defaultVal)
	assert.Equal(t, cty.String, defaultVal.Value().Type())
	assert.Equal(t, "boots", defaultVal.Value().AsString())

	// provider
	providerBlocks := blocks.OfType("provider")
	require.Len(t, providerBlocks, 1)
	assert.Equal(t, "provider", providerBlocks[0].Type())
	require.Len(t, providerBlocks[0].Labels(), 1)
	assert.Equal(t, "cats", providerBlocks[0].TypeLabel())

	// resources
	resourceBlocks := blocks.OfType("resource")

	sort.Slice(resourceBlocks, func(i, j int) bool {
		return resourceBlocks[i].TypeLabel() < resourceBlocks[j].TypeLabel()
	})

	require.Len(t, resourceBlocks, 2)
	require.Len(t, resourceBlocks[0].Labels(), 2)

	assert.Equal(t, "resource", resourceBlocks[0].Type())
	assert.Equal(t, "cats_cat", resourceBlocks[0].TypeLabel())
	assert.Equal(t, "mittens", resourceBlocks[0].NameLabel())

	assert.Equal(t, "mittens", resourceBlocks[0].GetAttribute("name").Value().AsString())
	assert.True(t, resourceBlocks[0].GetAttribute("special").Value().True())

	assert.Equal(t, "resource", resourceBlocks[1].Type())
	assert.Equal(t, "cats_kitten", resourceBlocks[1].TypeLabel())
	assert.Equal(t, "the great destroyer", resourceBlocks[1].GetAttribute("name").Value().AsString())
	assert.Equal(t, "mittens", resourceBlocks[1].GetAttribute("parent").Value().AsString())

	// import
	importBlocks := blocks.OfType("import")

	assert.Equal(t, "import", importBlocks[0].Type())
	require.NotNil(t, importBlocks[0].GetAttribute("to"))
	assert.Equal(t, "mittens", importBlocks[0].GetAttribute("id").Value().AsString())

	// data
	dataBlocks := blocks.OfType("data")
	require.Len(t, dataBlocks, 1)
	require.Len(t, dataBlocks[0].Labels(), 2)

	assert.Equal(t, "data", dataBlocks[0].Type())
	assert.Equal(t, "cats_cat", dataBlocks[0].TypeLabel())
	assert.Equal(t, "the-cats-mother", dataBlocks[0].NameLabel())

	assert.Equal(t, "boots", dataBlocks[0].GetAttribute("name").Value().AsString())

	// check
	checkBlocks := blocks.OfType("check")
	require.Len(t, checkBlocks, 1)
	require.Len(t, checkBlocks[0].Labels(), 1)

	assert.Equal(t, "check", checkBlocks[0].Type())
	assert.Equal(t, "cats_mittens_is_special", checkBlocks[0].TypeLabel())

	require.NotNil(t, checkBlocks[0].GetBlock("data"))
	require.NotNil(t, checkBlocks[0].GetBlock("assert"))
}

func Test_Modules(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "my-mod" {
	source = "../module"
	input = "ok"
}

output "result" {
	value = module.my-mod.mod_result
}
`,
		"module/module.tf": `
variable "input" {
	default = "?"
}

output "mod_result" {
	value = var.input
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true), options.ParserWithDebug(os.Stderr))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)

	require.Len(t, modules, 2)
	rootModule := modules[0]
	childModule := modules[1]

	moduleBlocks := rootModule.GetBlocks().OfType("module")
	require.Len(t, moduleBlocks, 1)

	assert.Equal(t, "module", moduleBlocks[0].Type())
	assert.Equal(t, "module.my-mod", moduleBlocks[0].FullName())
	inputAttr := moduleBlocks[0].GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	rootOutputs := rootModule.GetBlocks().OfType("output")
	require.Len(t, rootOutputs, 1)
	assert.Equal(t, "output.result", rootOutputs[0].FullName())
	valAttr := rootOutputs[0].GetAttribute("value")
	require.NotNil(t, valAttr)
	require.Equal(t, cty.String, valAttr.Type())
	assert.Equal(t, "ok", valAttr.Value().AsString())

	childOutputs := childModule.GetBlocks().OfType("output")
	require.Len(t, childOutputs, 1)
	assert.Equal(t, "module.my-mod.output.mod_result", childOutputs[0].FullName())
	childValAttr := childOutputs[0].GetAttribute("value")
	require.NotNil(t, childValAttr)
	require.Equal(t, cty.String, childValAttr.Type())
	assert.Equal(t, "ok", childValAttr.Value().AsString())

}

func Test_NestedParentModule(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
module "my-mod" {
	source = "../."
	input = "ok"
}

output "result" {
	value = module.my-mod.mod_result
}
`,
		"root.tf": `
variable "input" {
	default = "?"
}

output "mod_result" {
	value = var.input
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 2)
	rootModule := modules[0]
	childModule := modules[1]

	moduleBlocks := rootModule.GetBlocks().OfType("module")
	require.Len(t, moduleBlocks, 1)

	assert.Equal(t, "module", moduleBlocks[0].Type())
	assert.Equal(t, "module.my-mod", moduleBlocks[0].FullName())
	inputAttr := moduleBlocks[0].GetAttribute("input")
	require.NotNil(t, inputAttr)
	require.Equal(t, cty.String, inputAttr.Value().Type())
	assert.Equal(t, "ok", inputAttr.Value().AsString())

	rootOutputs := rootModule.GetBlocks().OfType("output")
	require.Len(t, rootOutputs, 1)
	assert.Equal(t, "output.result", rootOutputs[0].FullName())
	valAttr := rootOutputs[0].GetAttribute("value")
	require.NotNil(t, valAttr)
	require.Equal(t, cty.String, valAttr.Type())
	assert.Equal(t, "ok", valAttr.Value().AsString())

	childOutputs := childModule.GetBlocks().OfType("output")
	require.Len(t, childOutputs, 1)
	assert.Equal(t, "module.my-mod.output.mod_result", childOutputs[0].FullName())
	childValAttr := childOutputs[0].GetAttribute("value")
	require.NotNil(t, childValAttr)
	require.Equal(t, cty.String, childValAttr.Type())
	assert.Equal(t, "ok", childValAttr.Value().AsString())
}

func Test_UndefinedModuleOutputReference(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
resource "something" "blah" {
	value = module.x.y
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, false, attr.IsResolvable())
}

func Test_UndefinedModuleOutputReferenceInSlice(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
resource "something" "blah" {
	value = ["first", module.x.y, "last"]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, false, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_TemplatedSliceValue(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "hello"
}

resource "something" "blah" {
	value = ["first", "${var.x}-${var.x}", "last"]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "hello-hello", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_SliceOfVars(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "1"
}

variable "y" {
	default = "2"
}

resource "something" "blah" {
	value = [var.x, var.y]
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 2)

	assert.Equal(t, "1", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "2", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())
}

func Test_VarSlice(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = ["a", "b", "c"]
}

resource "something" "blah" {
	value = var.x
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_LocalSliceNested(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = "a"
}

locals {
	y = [var.x, "b", "c"]
}

resource "something" "blah" {
	value = local.y
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_FunctionCall(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `

variable "x" {
	default = ["a", "b"]
}

resource "something" "blah" {
	value = concat(var.x, ["c"])
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "code"))
	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)

	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.Equal(t, true, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.Equal(t, true, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.Equal(t, true, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.Equal(t, true, values[2].GetMetadata().IsResolvable())
}

func Test_NullDefaultValueForVar(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"test.tf": `
variable "bucket_name" {
  type    = string
  default = null
}

resource "aws_s3_bucket" "default" {
  bucket = var.bucket_name != null ? var.bucket_name : "default"
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))
	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("aws_s3_bucket")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("bucket")
	require.NotNil(t, attr)
	assert.Equal(t, "default", attr.Value().AsString())
}

func Test_MultipleInstancesOfSameResource(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"test.tf": `

resource "aws_kms_key" "key1" {
	description         = "Key #1"
	enable_key_rotation = true
}

resource "aws_kms_key" "key2" {
	description         = "Key #2"
	enable_key_rotation = true
}

resource "aws_s3_bucket" "this" {
	bucket        = "test"
  }


resource "aws_s3_bucket_server_side_encryption_configuration" "this1" {
	bucket = aws_s3_bucket.this.id
  
	rule {
	  apply_server_side_encryption_by_default {
		kms_master_key_id = aws_kms_key.key1.arn
		sse_algorithm     = "aws:kms"
	  }
	}
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this2" {
	bucket = aws_s3_bucket.this.id
  
	rule {
	  apply_server_side_encryption_by_default {
		kms_master_key_id = aws_kms_key.key2.arn
		sse_algorithm     = "aws:kms"
	  }
	}
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("aws_s3_bucket_server_side_encryption_configuration")
	assert.Len(t, blocks, 2)

	for _, block := range blocks {
		attr, parent := block.GetNestedAttribute("rule.apply_server_side_encryption_by_default.kms_master_key_id")
		assert.Equal(t, "apply_server_side_encryption_by_default", parent.Type())
		assert.NotNil(t, attr)
		assert.NotEmpty(t, attr.Value().AsString())
	}
}

func Test_IfConfigFsIsNotSet_ThenUseModuleFsForVars(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
variable "bucket_name" {
	type = string
}
resource "aws_s3_bucket" "main" {
	bucket = var.bucket_name
}
`,
		"main.tfvars": `bucket_name = "test_bucket"`,
	})
	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithTFVarsPaths("main.tfvars"),
	)

	require.NoError(t, parser.ParseFS(context.TODO(), "."))
	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]
	blocks := rootModule.GetResourcesByType("aws_s3_bucket")
	require.Len(t, blocks, 1)

	block := blocks[0]

	assert.Equal(t, "test_bucket", block.GetAttribute("bucket").AsStringValueOrDefault("", block).Value())
}

func Test_ForEachRefToLocals(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
locals {
  buckets = toset([
    "foo",
    "bar",
  ])
}

resource "aws_s3_bucket" "this" {
	for_each = local.buckets
	bucket   = each.key
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("aws_s3_bucket")
	assert.Len(t, blocks, 2)

	for _, block := range blocks {
		attr := block.GetAttribute("bucket")
		require.NotNil(t, attr)
		assert.Contains(t, []string{"foo", "bar"}, attr.AsStringValueOrDefault("", block).Value())
	}
}

func Test_ForEachRefToVariableWithDefault(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
variable "buckets" {
	type    = set(string)
	default = ["foo", "bar"]
}

resource "aws_s3_bucket" "this" {
	for_each = var.buckets
	bucket   = each.key
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("aws_s3_bucket")
	assert.Len(t, blocks, 2)

	for _, block := range blocks {
		attr := block.GetAttribute("bucket")
		require.NotNil(t, attr)
		assert.Contains(t, []string{"foo", "bar"}, attr.AsStringValueOrDefault("", block).Value())
	}
}

func Test_ForEachRefToVariableFromFile(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
variable "policy_rules" {
  type = object({
    secure_tags = optional(map(object({
      session_matcher        = optional(string)
      priority               = number
      enabled                = optional(bool, true)
    })), {})
  })
}

resource "google_network_security_gateway_security_policy_rule" "secure_tag_rules" {
  for_each               = var.policy_rules.secure_tags
  provider               = google-beta
  project                = "test"
  name                   = each.key
  enabled                = each.value.enabled
  priority               = each.value.priority
  session_matcher        = each.value.session_matcher
}
`,
		"main.tfvars": `
policy_rules = {
  secure_tags = {
    secure-tag-1 = {
      session_matcher = "host() != 'google.com'"
      priority        = 1001
    }
  }
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true), OptionWithTFVarsPaths("main.tfvars"))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("google_network_security_gateway_security_policy_rule")
	assert.Len(t, blocks, 1)

	block := blocks[0]

	assert.Equal(t, "secure-tag-1", block.GetAttribute("name").AsStringValueOrDefault("", block).Value())
	assert.Equal(t, true, block.GetAttribute("enabled").AsBoolValueOrDefault(false, block).Value())
	assert.Equal(t, "host() != 'google.com'", block.GetAttribute("session_matcher").AsStringValueOrDefault("", block).Value())
	assert.Equal(t, 1001, block.GetAttribute("priority").AsIntValueOrDefault(0, block).Value())
}

func Test_ForEachRefersToMapThatContainsSameStringValues(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `locals {
  buckets = {
    bucket1 = "test1"
    bucket2 = "test1"
  }
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket = each.key
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	bucketBlocks := modules.GetResourcesByType("aws_s3_bucket")
	assert.Len(t, bucketBlocks, 2)

	var labels []string

	for _, b := range bucketBlocks {
		labels = append(labels, b.Label())
	}

	expectedLabels := []string{
		`aws_s3_bucket.this["bucket1"]`,
		`aws_s3_bucket.this["bucket2"]`,
	}
	assert.Equal(t, expectedLabels, labels)
}

func TestDataSourceWithCountMetaArgument(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
data "http" "example" {
  count = 2
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	httpDataSources := rootModule.GetDatasByType("http")
	assert.Len(t, httpDataSources, 2)

	var labels []string
	for _, b := range httpDataSources {
		labels = append(labels, b.Label())
	}

	expectedLabels := []string{
		`http.example[0]`,
		`http.example[1]`,
	}
	assert.Equal(t, expectedLabels, labels)
}

func TestDataSourceWithForEachMetaArgument(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
locals {
	ports = ["80", "8080"]
}
data "http" "example" {
  for_each = toset(local.ports)
  url = "localhost:${each.key}"
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	httpDataSources := rootModule.GetDatasByType("http")
	assert.Len(t, httpDataSources, 2)
}

func TestForEach(t *testing.T) {
	tests := []struct {
		name               string
		src                string
		expectedBucketName string
		expectedNameLabel  string
	}{
		{
			name: "arg is set and ref to each.key",
			src: `locals {
	buckets = ["bucket1"]
}

resource "aws_s3_bucket" "this" {
	for_each = toset(local.buckets)
	bucket = each.key
}`,
			expectedBucketName: "bucket1",
			expectedNameLabel:  `this["bucket1"]`,
		},
		{
			name: "arg is set and ref to each.value",
			src: `locals {
	buckets = ["bucket1"]
}

resource "aws_s3_bucket" "this" {
	for_each = toset(local.buckets)
	bucket = each.value
}`,
			expectedBucketName: "bucket1",
			expectedNameLabel:  `this["bucket1"]`,
		},
		{
			name: "arg is map and ref to each.key",
			src: `locals {
	buckets = {
		bucket1key = "bucket1value"
	}
}

resource "aws_s3_bucket" "this" {
	for_each = local.buckets
	bucket = each.key
}`,
			expectedBucketName: "bucket1key",
			expectedNameLabel:  `this["bucket1key"]`,
		},
		{
			name: "arg is map and ref to each.value",
			src: `locals {
	buckets = {
		bucket1key = "bucket1value"
	}
}

resource "aws_s3_bucket" "this" {
	for_each = local.buckets
	bucket = each.value
}`,
			expectedBucketName: "bucket1value",
			expectedNameLabel:  `this["bucket1key"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := parse(t, map[string]string{
				"main.tf": tt.src,
			})
			require.Len(t, modules, 1)

			buckets := modules.GetResourcesByType("aws_s3_bucket")
			assert.Len(t, buckets, 1)

			bucket := buckets[0]
			bucketName := bucket.GetAttribute("bucket").Value().AsString()
			assert.Equal(t, tt.expectedBucketName, bucketName)

			assert.Equal(t, tt.expectedNameLabel, bucket.NameLabel())
		})
	}

}

func TestForEachCountExpanded(t *testing.T) {

	tests := []struct {
		name          string
		source        string
		expectedCount int
	}{
		{
			name: "arg is list of strings",
			source: `locals {
  buckets = ["bucket1", "bucket2"]
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket = each.key
}`,
			expectedCount: 2,
		},
		{
			name: "arg is empty list",
			source: `locals {
  buckets = []
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket   = each.value
}`,
			expectedCount: 0,
		},
		{
			name: "arg is empty set",
			source: `locals {
  buckets = toset([])
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket = each.key
}`,
			expectedCount: 0,
		},
		{
			name: "argument set with the same values",
			source: `locals {
  buckets = ["true", "true"]
}

resource "aws_s3_bucket" "this" {
  for_each = toset(local.buckets)
  bucket = each.key
}`,
			expectedCount: 1,
		},
		{
			name: "arg is non-valid set",
			source: `locals {
  buckets = [{
    bucket1key = "bucket1value"
  }]
}

resource "aws_s3_bucket" "this" {
	for_each = toset(local.buckets)
	bucket = each.value
}`,
			expectedCount: 0,
		},
		{
			name: "arg is set of strings",
			source: `locals {
  buckets = ["bucket1", "bucket2"]
}

resource "aws_s3_bucket" "this" {
  for_each = toset(local.buckets)
  bucket = each.key
}`,
			expectedCount: 2,
		},
		{
			name: "arg is map",
			source: `locals {
  buckets = {
    1 = {}
    2 = {}
  }
}

resource "aws_s3_bucket" "this" {
  for_each = local.buckets
  bucket = each.key
}`,
			expectedCount: 2,
		},
		{
			name: "arg is empty map",
			source: `locals {
	buckets = {}
}
resource "aws_s3_bucket" "this" {
	for_each = local.buckets
	bucket   = each.value
}
		`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := parse(t, map[string]string{
				"main.tf": tt.source,
			})
			assert.Len(t, modules, 1)

			bucketBlocks := modules.GetResourcesByType("aws_s3_bucket")
			assert.Len(t, bucketBlocks, tt.expectedCount)
		})
	}
}

func TestForEachRefToResource(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
	locals {
  vpcs = {
    "test1" = {
      cidr_block = "192.168.0.0/28"
    }
    "test2" = {
      cidr_block = "192.168.1.0/28"
    }
  }
}

resource "aws_vpc" "example" {
  for_each = local.vpcs
  cidr_block = each.value.cidr_block
}

resource "aws_internet_gateway" "example" {
  for_each = aws_vpc.example
  vpc_id = each.key
}
`,
	})
	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	require.Len(t, modules, 1)

	blocks := modules.GetResourcesByType("aws_internet_gateway")
	require.Len(t, blocks, 2)

	var vpcIds []string
	for _, b := range blocks {
		vpcIds = append(vpcIds, b.GetAttribute("vpc_id").Value().AsString())
	}

	expectedVpcIds := []string{"test1", "test2"}
	assert.Equal(t, expectedVpcIds, vpcIds)
}

func TestArnAttributeOfBucketIsCorrect(t *testing.T) {

	t.Run("the bucket doesn't have a name", func(t *testing.T) {
		fs := testutil.CreateFS(t, map[string]string{
			"main.tf": `resource "aws_s3_bucket" "this" {}`,
		})
		parser := New(fs, "", OptionStopOnHCLError(true))
		require.NoError(t, parser.ParseFS(context.TODO(), "."))

		modules, _, err := parser.EvaluateAll(context.TODO())
		require.NoError(t, err)
		require.Len(t, modules, 1)

		blocks := modules.GetResourcesByType("aws_s3_bucket")
		assert.Len(t, blocks, 1)

		bucket := blocks[0]

		values := bucket.Values()
		arnVal := values.GetAttr("arn")
		assert.True(t, arnVal.Type().Equals(cty.String))

		id := values.GetAttr("id").AsString()

		arn := arnVal.AsString()
		assert.Equal(t, "arn:aws:s3:::"+id, arn)
	})

	t.Run("the bucket has a name", func(t *testing.T) {
		fs := testutil.CreateFS(t, map[string]string{
			"main.tf": `resource "aws_s3_bucket" "this" {
  bucket = "test"
}

resource "aws_iam_role" "this" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "s3.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "this" {
  name   = "test_policy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.this.json
}

data "aws_iam_policy_document" "this" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }
}`,
		})
		parser := New(fs, "", OptionStopOnHCLError(true))
		require.NoError(t, parser.ParseFS(context.TODO(), "."))

		modules, _, err := parser.EvaluateAll(context.TODO())
		require.NoError(t, err)
		require.Len(t, modules, 1)

		blocks := modules[0].GetDatasByType("aws_iam_policy_document")
		assert.Len(t, blocks, 1)

		policyDoc := blocks[0]

		statement := policyDoc.GetBlock("statement")
		resources := statement.GetAttribute("resources").AsStringValueSliceOrEmpty()

		assert.Len(t, resources, 1)
		assert.True(t, resources[0].EqualTo("arn:aws:s3:::test/*"))
	})
}

func TestForEachWithObjectsOfDifferentTypes(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `module "backups" {
  bucket_name  = each.key
  client       = each.value.client
  path_writers = each.value.path_writers

  for_each = {
    "bucket1" = {
      client       = "client1"
      path_writers = ["writer1"] // tuple with string
    },
    "bucket2" = {
      client       = "client2"
      path_writers = [] // empty tuple
    }
  }
}
`,
	})
	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	assert.NoError(t, err)
	assert.Len(t, modules, 1)
}

func TestCountMetaArgument(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected int
	}{
		{
			name: "zero resources",
			src: `resource "test" "this" {
  count = 0
}`,
			expected: 0,
		},
		{
			name: "several resources",
			src: `resource "test" "this" {
  count = 2
}`,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(t, map[string]string{
				"main.tf": tt.src,
			})
			parser := New(fsys, "", OptionStopOnHCLError(true))
			require.NoError(t, parser.ParseFS(context.TODO(), "."))

			modules, _, err := parser.EvaluateAll(context.TODO())
			require.NoError(t, err)
			assert.Len(t, modules, 1)

			resources := modules.GetResourcesByType("test")
			assert.Len(t, resources, tt.expected)
		})
	}
}

func TestCountMetaArgumentInModule(t *testing.T) {
	tests := []struct {
		name                   string
		files                  map[string]string
		expectedCountModules   int
		expectedCountResources int
	}{
		{
			name: "zero modules",
			files: map[string]string{
				"main.tf": `module "this" {
  count = 0
  source = "./modules/test"
}`,
				"modules/test/main.tf": `resource "test" "this" {}`,
			},
			expectedCountModules:   1,
			expectedCountResources: 0,
		},
		{
			name: "several modules",
			files: map[string]string{
				"main.tf": `module "this" {
  count = 2
  source = "./modules/test"
}`,
				"modules/test/main.tf": `resource "test" "this" {}`,
			},
			expectedCountModules:   3,
			expectedCountResources: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := testutil.CreateFS(t, tt.files)
			parser := New(fsys, "", OptionStopOnHCLError(true))
			require.NoError(t, parser.ParseFS(context.TODO(), "."))

			modules, _, err := parser.EvaluateAll(context.TODO())
			require.NoError(t, err)

			assert.Len(t, modules, tt.expectedCountModules)

			resources := modules.GetResourcesByType("test")
			assert.Len(t, resources, tt.expectedCountResources)
		})
	}
}

func TestDynamicBlocks(t *testing.T) {
	t.Run("arg is list of int", func(t *testing.T) {
		modules := parse(t, map[string]string{
			"main.tf": `
resource "aws_security_group" "sg-webserver" {
  vpc_id = "1111"
  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`,
		})
		require.Len(t, modules, 1)

		secGroups := modules.GetResourcesByType("aws_security_group")
		assert.Len(t, secGroups, 1)
		ingressBlocks := secGroups[0].GetBlocks("ingress")
		assert.Len(t, ingressBlocks, 2)

		var inboundPorts []int
		for _, ingress := range ingressBlocks {
			fromPort := ingress.GetAttribute("from_port").AsIntValueOrDefault(-1, ingress).Value()
			inboundPorts = append(inboundPorts, fromPort)
		}

		assert.True(t, compareSets([]int{80, 443}, inboundPorts))
	})

	t.Run("empty for-each", func(t *testing.T) {
		modules := parse(t, map[string]string{
			"main.tf": `
resource "aws_lambda_function" "analyzer" {
  dynamic "vpc_config" {
    for_each = []
    content {}
  }
}
`,
		})
		require.Len(t, modules, 1)

		functions := modules.GetResourcesByType("aws_lambda_function")
		assert.Len(t, functions, 1)
		vpcConfigs := functions[0].GetBlocks("vpc_config")
		assert.Empty(t, vpcConfigs)
	})

	t.Run("arg is list of bool", func(t *testing.T) {
		modules := parse(t, map[string]string{
			"main.tf": `
resource "aws_lambda_function" "analyzer" {
  dynamic "vpc_config" {
    for_each = [true]
    content {}
  }
}
`,
		})
		require.Len(t, modules, 1)

		functions := modules.GetResourcesByType("aws_lambda_function")
		assert.Len(t, functions, 1)
		vpcConfigs := functions[0].GetBlocks("vpc_config")
		assert.Len(t, vpcConfigs, 1)
	})

	t.Run("arg is list of objects", func(t *testing.T) {
		modules := parse(t, map[string]string{
			"main.tf": `locals {
  cluster_network_policy = [{
    enabled = true
  }]
}

resource "google_container_cluster" "primary" {
  name = "test"

  dynamic "network_policy" {
    for_each = local.cluster_network_policy

    content {
      enabled = network_policy.value.enabled
    }
  }
}`,
		})
		require.Len(t, modules, 1)

		clusters := modules.GetResourcesByType("google_container_cluster")
		assert.Len(t, clusters, 1)

		networkPolicies := clusters[0].GetBlocks("network_policy")
		assert.Len(t, networkPolicies, 1)

		enabled := networkPolicies[0].GetAttribute("enabled")
		assert.True(t, enabled.Value().True())
	})

	t.Run("nested dynamic", func(t *testing.T) {
		modules := parse(t, map[string]string{
			"main.tf": `
resource "test_block" "this" {
  name     = "name"
  location = "loc"
  dynamic "env" {
	for_each = ["1", "2"]
	content {
	  dynamic "value_source" {
		for_each = [true, true]
		content {}
	  }
	}
  }
}`,
		})
		require.Len(t, modules, 1)

		testResources := modules.GetResourcesByType("test_block")
		assert.Len(t, testResources, 1)
		envs := testResources[0].GetBlocks("env")
		assert.Len(t, envs, 2)

		var sources []*terraform.Block
		for _, env := range envs {
			sources = append(sources, env.GetBlocks("value_source")...)
		}
		assert.Len(t, sources, 4)
	})
}

func parse(t *testing.T, files map[string]string) terraform.Modules {
	fs := testutil.CreateFS(t, files)
	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)

	return modules
}

func compareSets(a []int, b []int) bool {
	m := make(map[int]bool)
	for _, el := range a {
		m[el] = true
	}

	for _, el := range b {
		if !m[el] {
			return false
		}
	}

	return true
}
