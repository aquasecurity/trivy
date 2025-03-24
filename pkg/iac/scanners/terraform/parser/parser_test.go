package parser

import (
	"bytes"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	tfcontext "github.com/aquasecurity/trivy/pkg/iac/terraform/context"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))
	modules, _, err := parser.EvaluateAll(t.Context())
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

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "code"))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.False(t, attr.IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.False(t, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.True(t, values[2].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "first", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "hello-hello", values[1].Value())
	assert.True(t, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "last", values[2].Value())
	assert.True(t, values[2].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 2)

	assert.Equal(t, "1", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "2", values[1].Value())
	assert.True(t, values[1].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.True(t, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.True(t, values[2].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.True(t, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.True(t, values[2].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	attr := block.GetAttribute("value")
	require.NotNil(t, attr)

	assert.True(t, attr.IsResolvable())

	values := attr.AsStringValueSliceOrEmpty()
	require.Len(t, values, 3)

	assert.Equal(t, "a", values[0].Value())
	assert.True(t, values[0].GetMetadata().IsResolvable())

	assert.Equal(t, "b", values[1].Value())
	assert.True(t, values[1].GetMetadata().IsResolvable())

	assert.Equal(t, "c", values[2].Value())
	assert.True(t, values[2].GetMetadata().IsResolvable())
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))
	modules, _, err := parser.EvaluateAll(t.Context())
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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

	require.NoError(t, parser.ParseFS(t.Context(), "."))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("google_network_security_gateway_security_policy_rule")
	assert.Len(t, blocks, 1)

	block := blocks[0]

	assert.Equal(t, "secure-tag-1", block.GetAttribute("name").AsStringValueOrDefault("", block).Value())
	assert.True(t, block.GetAttribute("enabled").AsBoolValueOrDefault(false, block).Value())
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
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
		require.NoError(t, parser.ParseFS(t.Context(), "."))

		modules, _, err := parser.EvaluateAll(t.Context())
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
		require.NoError(t, parser.ParseFS(t.Context(), "."))

		modules, _, err := parser.EvaluateAll(t.Context())
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
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
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
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			modules, _, err := parser.EvaluateAll(t.Context())
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
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			modules, _, err := parser.EvaluateAll(t.Context())
			require.NoError(t, err)

			assert.Len(t, modules, tt.expectedCountModules)

			resources := modules.GetResourcesByType("test")
			assert.Len(t, resources, tt.expectedCountResources)
		})
	}
}

func TestDynamicBlocks(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected []any
	}{
		{
			name: "for-each use tuple of int",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = [80, 443]
    content {
      bar = foo.value
    }
  }
}`,
			expected: []any{float64(80), float64(443)},
		},
		{
			name: "for-each use list of int",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = tolist([80, 443])
    content {
      bar = foo.value
    }
  }
}`,
			expected: []any{float64(80), float64(443)},
		},
		{
			name: "for-each use set of int",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = toset([80, 443])
    content {
      bar = foo.value
    }
  }
}`,
			expected: []any{float64(80), float64(443)},
		},
		{
			name: "for-each use list of bool",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = tolist([true])
    content {
      bar = foo.value
    }
  }
}`,
			expected: []any{true},
		},
		{
			name: "empty for-each",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = []
    content {}
  }
}`,
			expected: []any{},
		},
		{
			name: "for-each use tuple of objects",
			src: `variable "test_var" {
  type    = list(object({ enabled = bool }))
  default = [{ enabled = true }]
}

resource "test_resource" "test" {
  dynamic "foo" {
    for_each = var.test_var

    content {
      bar = foo.value.enabled
    }
  }
}`,
			expected: []any{true},
		},
		{
			name: "attribute ref to object key",
			src: `variable "some_var" {
  type = map(
    object({
      tag = string
    })
  )
  default = {
    ssh   = { "tag" = "login" }
    http  = { "tag" = "proxy" }
    https = { "tag" = "proxy" }
  }
}

resource "test_resource" "test" {
  dynamic "foo" {
    for_each = { for name, values in var.some_var : name => values }
    content {
      bar = foo.key
    }
  }
}`,
			expected: []any{"ssh", "http", "https"},
		},
		{
			name: "attribute ref to object value",
			src: `variable "some_var" {
  type = map(
    object({
      tag = string
    })
  )
  default = {
    ssh   = { "tag" = "login" }
    http  = { "tag" = "proxy" }
    https = { "tag" = "proxy" }
  }
}

resource "test_resource" "test" {
  dynamic "foo" {
    for_each = { for name, values in var.some_var : name => values }
    content {
      bar = foo.value.tag
    }
  }
}`,
			expected: []any{"login", "proxy", "proxy"},
		},
		{
			name: "attribute ref to map key",
			src: `variable "some_var" {
  type = map
  default = {
    ssh   = { "tag" = "login" }
    http  = { "tag" = "proxy" }
    https = { "tag" = "proxy" }
  }
}

resource "test_resource" "test" {
  dynamic "foo" {
    for_each = var.some_var
    content {
      bar = foo.key
    }
  }
}`,
			expected: []any{"ssh", "http", "https"},
		},
		{
			name: "attribute ref to map value",
			src: `variable "some_var" {
  type = map
  default = {
    ssh   = { "tag" = "login" }
    http  = { "tag" = "proxy" }
    https = { "tag" = "proxy" }
  }
}

resource "test_resource" "test" {
  dynamic "foo" {
    for_each = var.some_var
    content {
      bar = foo.value.tag
    }
  }
}`,
			expected: []any{"login", "proxy", "proxy"},
		},
		{
			name: "dynamic block with iterator",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = ["foo", "bar"]
	iterator = some_iterator
    content {
      bar = some_iterator.value
    }
  }
}`,
			expected: []any{"foo", "bar"},
		},
		{
			name: "iterator and parent block with same name",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = ["foo", "bar"]
	iterator = foo
    content {
      bar = foo.value
    }
  }
}`,
			expected: []any{"foo", "bar"},
		},
		{
			name: "for-each use null value",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = null
    content {
      bar = foo.value
	}
  }
}`,
			expected: []any{},
		},
		{
			name: "no for-each attribute",
			src: `resource "test_resource" "test" {
  dynamic "foo" {
    content {
      bar = foo.value
	}
  }
}`,
			expected: []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := parse(t, map[string]string{
				"main.tf": tt.src,
			})
			require.Len(t, modules, 1)

			resource := modules.GetResourcesByType("test_resource")
			require.Len(t, resource, 1)
			blocks := resource[0].GetBlocks("foo")

			var vals []any
			for _, attr := range blocks {
				vals = append(vals, attr.GetAttribute("bar").GetRawValue())
			}

			assert.ElementsMatch(t, tt.expected, vals)
		})
	}
}

func TestNestedDynamicBlock(t *testing.T) {
	modules := parse(t, map[string]string{
		"main.tf": `resource "test_resource" "test" {
  dynamic "foo" {
    for_each = ["1", "1"]
    content {
      dynamic "bar" {
        for_each = [true, true]
        content {
          baz = foo.value
          qux = bar.value
        }
      }
    }
  }
}`,
	})
	require.Len(t, modules, 1)

	testResources := modules.GetResourcesByType("test_resource")
	assert.Len(t, testResources, 1)
	blocks := testResources[0].GetBlocks("foo")
	assert.Len(t, blocks, 2)

	var nested []*terraform.Block
	for _, block := range blocks {
		nested = append(nested, block.GetBlocks("bar")...)
		for _, b := range nested {
			assert.Equal(t, "1", b.GetAttribute("baz").GetRawValue())
			assert.Equal(t, true, b.GetAttribute("qux").GetRawValue())
		}
	}
	assert.Len(t, nested, 4)
}

func parse(t *testing.T, files map[string]string, opts ...Option) terraform.Modules {
	fs := testutil.CreateFS(t, files)
	opts = append(opts, OptionStopOnHCLError(true))
	parser := New(fs, "", opts...)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	return modules
}

func TestModuleRefersToOutputOfAnotherModule(t *testing.T) {
	files := map[string]string{
		"main.tf": `
module "module2" {
	source = "./modules/foo"
}

module "module1" {
	source = "./modules/bar"
	test_var = module.module2.test_out
}
`,
		"modules/foo/main.tf": `
output "test_out" {
	value = "test_value"
}
`,
		"modules/bar/main.tf": `
variable "test_var" {}

resource "test_resource" "this" {
	dynamic "dynamic_block" {
		for_each = [var.test_var]
		content {
			some_attr = dynamic_block.value
		}
	}
}
`,
	}

	modules := parse(t, files)
	require.Len(t, modules, 3)

	resources := modules.GetResourcesByType("test_resource")
	require.Len(t, resources, 1)

	attr, _ := resources[0].GetNestedAttribute("dynamic_block.some_attr")
	require.NotNil(t, attr)

	assert.Equal(t, "test_value", attr.GetRawValue())
}

// TestNestedModulesOptions ensures parser options are carried to the nested
// submodule evaluators.
// The test will include an invalid module that will fail to download
// if it is attempted.
func TestNestedModulesOptions(t *testing.T) {
	// reset the previous default logger
	prevLog := slog.Default()
	defer slog.SetDefault(prevLog)
	var buf bytes.Buffer
	slog.SetDefault(slog.New(log.NewHandler(&buf, nil)))

	// Folder structure
	// ./
	// ├── main.tf
	// └── modules
	//     ├── city
	//     │   └── main.tf
	//     ├── queens
	//     │   └── main.tf
	//     └── brooklyn
	//         └── main.tf
	//
	// Modules referenced
	// main -> city ├─> brooklyn
	//              └─> queens
	files := map[string]string{
		"main.tf": `
module "city" {
	source = "./modules/city"
}

resource "city" "neighborhoods" {
	names = module.city.neighborhoods
}
`,
		"modules/city/main.tf": `
module "brooklyn" {
	source = "./brooklyn"
}

module "queens" {
	source = "./queens"
}

output "neighborhoods" {
	value = [module.brooklyn.name, module.queens.name]
}
`,
		"modules/city/brooklyn/main.tf": `
output "name" {
	value = "Brooklyn"
}
`,
		"modules/city/queens/main.tf": `
output "name" {
	value = "Queens"
}

module "invalid" {
	source         = "https://example.invaliddomain"
}
`,
	}

	// Using the OptionWithDownloads(false) option will prevent the invalid
	// module from being downloaded. If the log exists "failed to download"
	// then the submodule evaluator attempted to download, which was disallowed.
	modules := parse(t, files, OptionWithDownloads(false))
	require.Len(t, modules, 4)

	resources := modules.GetResourcesByType("city")
	require.Len(t, resources, 1)

	for _, res := range resources {
		attr, _ := res.GetNestedAttribute("names")
		require.NotNil(t, attr, res.FullName())
		assert.Equal(t, []string{"Brooklyn", "Queens"}, attr.GetRawValue())
	}

	require.NotContains(t, buf.String(), "failed to download")

	// Verify module parents are set correctly.
	expectedParents := map[string]string{
		".":                     "",
		"modules/city":          ".",
		"modules/city/brooklyn": "modules/city",
		"modules/city/queens":   "modules/city",
	}

	for _, mod := range modules {
		expected, exists := expectedParents[mod.ModulePath()]
		require.Truef(t, exists, "module %s does not exist in assertion", mod.ModulePath())
		if expected == "" {
			require.Nil(t, mod.Parent())
		} else {
			require.Equal(t, expected, mod.Parent().ModulePath(), "parent of module %q", mod.ModulePath())
		}
	}
}

// TestModuleParents sets up a nested module structure and verifies the
// parent-child relationships are correctly set.
func TestModuleParents(t *testing.T) {
	// The setup is a list of continents, some countries, some cities, etc.
	dirfs := os.DirFS("./testdata/nested")
	parser := New(dirfs, "",
		OptionStopOnHCLError(true),
		OptionWithDownloads(false),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	// modules only have 'parent'. They do not have children, so create
	// a structure that allows traversal from the root to the leafs.
	modChildren := make(map[*terraform.Module][]*terraform.Module)
	// Keep track of every module that exists
	modSet := set.New[*terraform.Module]()
	var root *terraform.Module
	for _, mod := range modules {
		mod := mod
		modChildren[mod] = make([]*terraform.Module, 0)
		modSet.Append(mod)

		if mod.Parent() == nil {
			// Only 1 root should exist
			require.Nil(t, root, "root module already set")
			root = mod
		}
		modChildren[mod.Parent()] = append(modChildren[mod.Parent()], mod)
	}

	type node struct {
		prefix     string
		modulePath string
		children   []node
	}

	// expectedTree is the full module tree structure.
	expectedTree := node{
		modulePath: ".",
		children: []node{
			{
				modulePath: "north-america",
				children: []node{
					{
						modulePath: "north-america/united-states",
						children: []node{
							{modulePath: "north-america/united-states/springfield", prefix: "illinois-"},
							{modulePath: "north-america/united-states/springfield", prefix: "idaho-"},
							{modulePath: "north-america/united-states/new-york", children: []node{
								{modulePath: "north-america/united-states/new-york/new-york-city"},
							}},
						},
					},
					{
						modulePath: "north-america/canada",
						children: []node{
							{modulePath: "north-america/canada/springfield", prefix: "ontario-"},
						},
					},
				},
			},
		},
	}

	var assertChild func(t *testing.T, n node, mod *terraform.Module)
	assertChild = func(t *testing.T, n node, mod *terraform.Module) {
		modSet.Remove(mod)
		children := modChildren[mod]

		t.Run(n.modulePath, func(t *testing.T) {
			if !assert.Equal(t, len(n.children), len(children), "modChildren count for %s", n.modulePath) {
				return
			}
			for _, child := range children {
				// Find the child module that we are expecting.
				idx := slices.IndexFunc(n.children, func(node node) bool {
					outputBlocks := child.GetBlocks().OfType("output")
					outIdx := slices.IndexFunc(outputBlocks, func(outputBlock *terraform.Block) bool {
						return outputBlock.Labels()[0] == "name"
					})
					if outIdx == -1 {
						return false
					}

					output := outputBlocks[outIdx]
					outVal := output.GetAttribute("value").Value()
					if !outVal.Type().Equals(cty.String) {
						return false
					}

					modName := filepath.Base(node.modulePath)
					if outVal.AsString() != node.prefix+modName {
						return false
					}

					return node.modulePath == child.ModulePath()
				})
				if !assert.NotEqualf(t, -1, idx, "module prefix=%s path=%s not found in %s", n.prefix, child.ModulePath(), n.modulePath) {
					continue
				}

				assertChild(t, n.children[idx], child)
			}
		})

	}

	assertChild(t, expectedTree, root)
	// If any module was not asserted, the test will fail. This ensures the
	// entire module tree is checked.
	require.Equal(t, 0, modSet.Size(), "all modules asserted")
}

func TestCyclicModules(t *testing.T) {
	files := map[string]string{
		"main.tf": `
module "module2" {
	source = "./modules/foo"
	test_var = passthru.handover.from_1
}

// Demonstrates need for evaluateSteps between submodule evaluations.
resource "passthru" "handover" {
	from_1 = module.module1.test_out
	from_2 = module.module2.test_out
}

module "module1" {
	source = "./modules/bar"
	test_var = passthru.handover.from_2
}
`,
		"modules/foo/main.tf": `
variable "test_var" {}

resource "test_resource" "this" {
	dynamic "dynamic_block" {
		for_each = [var.test_var]
		content {
			some_attr = dynamic_block.value
		}
	}
}

output "test_out" {
	value = "test_value"
}
`,
		"modules/bar/main.tf": `
variable "test_var" {}

resource "test_resource" "this" {
	dynamic "dynamic_block" {
		for_each = [var.test_var]
		content {
			some_attr = dynamic_block.value
		}
	}
}

output "test_out" {
	value = test_resource.this.dynamic_block.some_attr
}
`,
	}

	modules := parse(t, files)
	require.Len(t, modules, 3)

	resources := modules.GetResourcesByType("test_resource")
	require.Len(t, resources, 2)

	for _, res := range resources {
		attr, _ := res.GetNestedAttribute("dynamic_block.some_attr")
		require.NotNil(t, attr, res.FullName())
		assert.Equal(t, "test_value", attr.GetRawValue())
	}
}

func TestExtractSetValue(t *testing.T) {
	files := map[string]string{
		"main.tf": `
resource "test" "set-value" {
	value = toset(["x", "y", "x"])
}
`,
	}

	resources := parse(t, files).GetResourcesByType("test")
	require.Len(t, resources, 1)
	attr := resources[0].GetAttribute("value")
	require.NotNil(t, attr)
	assert.Equal(t, []string{"x", "y"}, attr.GetRawValue())
}

func TestFunc_fileset(t *testing.T) {
	files := map[string]string{
		"main.tf": `
resource "test" "fileset-func" {
	value = fileset(path.module, "**/*.py")
}
`,
		"a.py":      ``,
		"path/b.py": ``,
	}

	resources := parse(t, files).GetResourcesByType("test")
	require.Len(t, resources, 1)
	attr := resources[0].GetAttribute("value")
	require.NotNil(t, attr)
	assert.Equal(t, []string{"a.py", "path/b.py"}, attr.GetRawValue())
}

func TestExprWithMissingVar(t *testing.T) {
	files := map[string]string{
		"main.tf": `
variable "v" {
	type = string
}

resource "test" "values" {
	s = "foo-${var.v}"
    l1 = ["foo", var.v]
    l2 = concat(["foo"], [var.v])
    d1 = {foo = var.v}
    d2 = merge({"foo": "bar"}, {"baz": var.v})
}
`,
	}

	resources := parse(t, files).GetResourcesByType("test")
	require.Len(t, resources, 1)

	s_attr := resources[0].GetAttribute("s")
	require.NotNil(t, s_attr)
	assert.Equal(t, "foo-", s_attr.GetRawValue())

	for _, name := range []string{"l1", "l2", "d1", "d2"} {
		attr := resources[0].GetAttribute(name)
		require.NotNil(t, attr)
	}
}

func TestVarTypeShortcut(t *testing.T) {
	files := map[string]string{
		"main.tf": `
variable "magic_list" {
	type    = list
	default = ["x", "y"]
}

variable "magic_map" {
	type    = map
	default = {a = 1, b = 2}
}

resource "test" "values" {
	l = var.magic_list
	m = var.magic_map
}
`,
	}

	resources := parse(t, files).GetResourcesByType("test")
	require.Len(t, resources, 1)

	list_attr := resources[0].GetAttribute("l")
	require.NotNil(t, list_attr)
	assert.Equal(t, []string{"x", "y"}, list_attr.GetRawValue())

	map_attr := resources[0].GetAttribute("m")
	require.NotNil(t, map_attr)
	assert.True(t, map_attr.Value().RawEquals(cty.MapVal(map[string]cty.Value{
		"a": cty.NumberIntVal(1), "b": cty.NumberIntVal(2),
	})))
}

func Test_LoadLocalCachedModule(t *testing.T) {
	fsys := os.DirFS(filepath.Join("testdata", "cached-modules"))

	parser := New(
		fsys, "",
		OptionStopOnHCLError(true),
		OptionWithDownloads(false),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	assert.Len(t, modules, 2)

	buckets := modules.GetResourcesByType("aws_s3_bucket")
	assert.Len(t, buckets, 1)

	assert.Equal(t, "my-private-module/s3-bucket/aws/.terraform/modules/s3-bucket/main.tf", buckets[0].GetMetadata().Range().GetFilename())

	bucketName := buckets[0].GetAttribute("bucket").Value().AsString()
	assert.Equal(t, "my-s3-bucket", bucketName)
}

func TestTFVarsFileDoesNotExist(t *testing.T) {
	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{
			Data: []byte(``),
		},
	}

	parser := New(
		fsys, "",
		OptionStopOnHCLError(true),
		OptionWithDownloads(false),
		OptionWithTFVarsPaths("main.tfvars"),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	_, _, err := parser.EvaluateAll(t.Context())
	assert.ErrorContains(t, err, "file does not exist")
}

func Test_OptionsWithEvalHook(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `
data "your_custom_data" "this" {
  default = ["foo", "foh", "fum"]
  unaffected = "bar"
}

// Testing the hook affects some value, which is used in another evaluateStep
// action (expanding blocks)
data "random_thing" "that" {
  dynamic "repeated" {
    for_each = data.your_custom_data.this.value
	content {
      value = repeated.value
	}
  }
}

locals {
	referenced = data.your_custom_data.this.value
	static_ref = data.your_custom_data.this.unaffected
}
`})

	parser := New(fs, "", OptionWithEvalHook(
		// A basic example of how to have a 'default' value for a data block.
		// To see a more practical example, see how 'evaluateVariable' handles
		// the 'default' value of a variable.
		func(ctx *tfcontext.Context, blocks terraform.Blocks, inputVars map[string]cty.Value) {
			dataBlocks := blocks.OfType("data")
			for _, block := range dataBlocks {
				if len(block.Labels()) >= 1 && block.Labels()[0] == "your_custom_data" {
					def := block.GetAttribute("default")
					ctx.Set(cty.ObjectVal(map[string]cty.Value{
						"value": def.Value(),
					}), "data", "your_custom_data", "this")
				}
			}

		},
	))

	require.NoError(t, parser.ParseFS(context.TODO(), "."))

	modules, _, err := parser.EvaluateAll(context.TODO())
	require.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	// Check the default value of the data block
	blocks := rootModule.GetDatasByType("your_custom_data")
	assert.Len(t, blocks, 1)
	expList := cty.TupleVal([]cty.Value{cty.StringVal("foo"), cty.StringVal("foh"), cty.StringVal("fum")})
	assert.True(t, expList.Equals(blocks[0].GetAttribute("default").Value()).True(), "default value matched list")
	assert.Equal(t, "bar", blocks[0].GetAttribute("unaffected").Value().AsString())

	// Check the referenced 'data.your_custom_data.this.value' exists in the eval
	// context, and it is the default value of the data block.
	locals := rootModule.GetBlocks().OfType("locals")
	assert.Len(t, locals, 1)
	assert.True(t, expList.Equals(locals[0].GetAttribute("referenced").Value()).True(), "referenced value matched list")
	assert.Equal(t, "bar", locals[0].GetAttribute("static_ref").Value().AsString())

	// Check the dynamic block is expanded correctly
	dynamicBlocks := rootModule.GetDatasByType("random_thing")
	assert.Len(t, dynamicBlocks, 1)
	assert.Len(t, dynamicBlocks[0].GetBlocks("repeated"), 3)
	for i, repeat := range dynamicBlocks[0].GetBlocks("repeated") {
		assert.Equal(t, expList.Index(cty.NumberIntVal(int64(i))), repeat.GetAttribute("value").Value())
	}
}

func Test_OptionsWithTfVars(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": `resource "test" "this" {
  foo = var.foo
}
variable "foo" {}
`})

	parser := New(fs, "", OptionsWithTfVars(
		map[string]cty.Value{
			"foo": cty.StringVal("bar"),
		},
	))

	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	assert.Len(t, modules, 1)

	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("test")
	assert.Len(t, blocks, 1)
	assert.Equal(t, "bar", blocks[0].GetAttribute("foo").Value().AsString())
}

func Test_AWSRegionNameDefined(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/test.tf": `
data "aws_region" "current" {}

data "aws_region" "other" {
  name = "us-east-2"
}

resource "something" "blah" {
  r1 = data.aws_region.current.name
  r2 = data.aws_region.other.name
}
`,
	})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "code"))
	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	rootModule := modules[0]

	blocks := rootModule.GetResourcesByType("something")
	require.Len(t, blocks, 1)
	block := blocks[0]

	r1 := block.GetAttribute("r1")
	require.NotNil(t, r1)
	assert.True(t, r1.IsResolvable())
	assert.Equal(t, "current-region", r1.Value().AsString())

	r2 := block.GetAttribute("r2")
	require.NotNil(t, r2)
	assert.True(t, r2.IsResolvable())
	assert.Equal(t, "us-east-2", r2.Value().AsString())
}

func TestLogAboutMissingVariableValues(t *testing.T) {
	var buf bytes.Buffer
	slog.SetDefault(slog.New(log.NewHandler(&buf, nil)))

	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{
			Data: []byte(`
variable "foo" {}

variable "bar" {
  default = "bar"
}

variable "baz" {}
`),
		},
		"main.tfvars": &fstest.MapFile{
			Data: []byte(`baz = "baz"`),
		},
	}

	parser := New(
		fsys, "",
		OptionStopOnHCLError(true),
		OptionWithTFVarsPaths("main.tfvars"),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	_, err := parser.Load(t.Context())
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "Variable values was not found in the environment or variable files.")
	assert.Contains(t, buf.String(), "variables=\"foo\"")
}

func TestLoadChildModulesFromLocalCache(t *testing.T) {
	var buf bytes.Buffer
	slog.SetDefault(slog.New(log.NewHandler(&buf, &log.Options{Level: log.LevelDebug})))

	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`module "level_1" {
  source = "./modules/level_1"
}`)},
		"modules/level_1/main.tf": &fstest.MapFile{Data: []byte(`module "level_2" {
  source  = "../level_2"
}`)},
		"modules/level_2/main.tf": &fstest.MapFile{Data: []byte(`module "level_3" {
  count = 2
  source  = "../level_3"
}`)},
		"modules/level_3/main.tf": &fstest.MapFile{Data: []byte(`resource "foo" "bar" {}`)},
		".terraform/modules/modules.json": &fstest.MapFile{Data: []byte(`{
    "Modules": [
        { "Key": "", "Source": "", "Dir": "." },
        {
            "Key": "level_1",
            "Source": "./modules/level_1",
            "Dir": "modules/level_1"
        },
        {
            "Key": "level_1.level_2",
            "Source": "../level_2",
            "Dir": "modules/level_2"
        },
        {
            "Key": "level_1.level_2.level_3",
            "Source": "../level_3",
            "Dir": "modules/level_3"
        }
    ]
}`)},
	}

	parser := New(
		fsys, "",
		OptionStopOnHCLError(true),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	assert.Len(t, modules, 5)

	assert.Contains(t, buf.String(), "Using module from Terraform cache .terraform/modules\tsource=\"./modules/level_1\"")
	assert.Contains(t, buf.String(), "Using module from Terraform cache .terraform/modules\tsource=\"../level_2\"")
	assert.Contains(t, buf.String(), "Using module from Terraform cache .terraform/modules\tsource=\"../level_3\"")
	assert.Contains(t, buf.String(), "Using module from Terraform cache .terraform/modules\tsource=\"../level_3\"")
}

func TestLogParseErrors(t *testing.T) {
	var buf bytes.Buffer
	slog.SetDefault(slog.New(log.NewHandler(&buf, nil)))

	src := `resource "aws-s3-bucket" "name" {
  bucket = <
}`

	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{
			Data: []byte(src),
		},
	}

	parser := New(fsys, "")
	err := parser.ParseFS(t.Context(), ".")
	require.NoError(t, err)

	assert.Contains(t, buf.String(), `cause="  bucket = <"`)
}

func Test_PassingNullToChildModule_DoesNotEraseType(t *testing.T) {
	tests := []struct {
		name string
		fsys fs.FS
	}{
		{
			name: "typed variable",
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`module "test" {
  source   = "./modules/test"
  test_var = null
}`)},
				"modules/test/main.tf": &fstest.MapFile{Data: []byte(`variable "test_var" {
  type    = number
}

resource "foo" "this" {
  bar = var.test_var != null ? 1 : 2
}`)},
			},
		},
		{
			name: "typed variable with default",
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`module "test" {
  source   = "./modules/test"
  test_var = null
}`)},
				"modules/test/main.tf": &fstest.MapFile{Data: []byte(`variable "test_var" {
  type    = number
  default = null
}

resource "foo" "this" {
  bar = var.test_var != null ? 1 : 2
}`)},
			},
		},
		{
			name: "empty variable",
			fsys: fstest.MapFS{
				"main.tf": &fstest.MapFile{Data: []byte(`module "test" {
  source   = "./modules/test"
  test_var = null
}`)},
				"modules/test/main.tf": &fstest.MapFile{Data: []byte(`variable "test_var" {}

resource "foo" "this" {
  bar = var.test_var != null ? 1 : 2
}`)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := New(
				tt.fsys, "",
				OptionStopOnHCLError(true),
			)
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			_, err := parser.Load(t.Context())
			require.NoError(t, err)

			modules, _, err := parser.EvaluateAll(t.Context())
			require.NoError(t, err)

			res := modules.GetResourcesByType("foo")[0]
			attr := res.GetAttribute("bar")
			val, _ := attr.Value().AsBigFloat().Int64()
			assert.Equal(t, int64(2), val)
		})
	}
}

func TestAttrRefToNullVariable(t *testing.T) {
	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`variable "name" {
  type    = string
  default = null
}

resource "aws_s3_bucket" "example" {
  bucket = var.name
}`)},
	}

	parser := New(fsys, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	_, err := parser.Load(t.Context())
	require.NoError(t, err)

	modules, _, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)

	val := modules.GetResourcesByType("aws_s3_bucket")[0].GetAttribute("bucket").GetRawValue()
	assert.Nil(t, val)
}

func TestConfigWithEphemeralBlock(t *testing.T) {
	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`ephemeral "random_password" "password" {
  length = 16
}`)},
	}

	parser := New(fsys, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	_, err := parser.Load(t.Context())
	require.NoError(t, err)
}

func TestConvertObjectWithUnknownAndNullValuesToMap(t *testing.T) {
	fsys := fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(`module "foo" {
  source = "./modules/foo"
}

locals {
  known = "test"
}

module "bar" {
  source = "./modules/bar"
  outputs = {
    "key1" : { "Value" : module.foo.test },
    "key2" : { "Value" : local.known },
    "key3" : { "Value" : local.unknown },
  }
}`)},
		"modules/foo/main.tf": &fstest.MapFile{Data: []byte(`output "test" {
  value       = ref_to_unknown
}`)},
		"modules/bar/main.tf": &fstest.MapFile{Data: []byte(`variable "outputs" {
  type        = map(any)
}`)},
	}

	parser := New(fsys, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	_, err := parser.Load(t.Context())
	require.NoError(t, err)

	_, _, err = parser.EvaluateAll(t.Context())
	require.NoError(t, err)
}
