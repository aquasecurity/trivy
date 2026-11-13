package parser

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/log"
)

func TestLoadModuleTree(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"main.tf": `
module "a" {
  for_each = toset(["x", "y"])
  source   = "./modules/a"
}
`,
		"modules/a/main.tf": `
module "b" {
  count  = 2
  source = "../b"
}
`,
		"modules/b/main.tf": `resource "foo" "bar" {}`,
	})

	parser := New(fsys, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	root := parser.loadModuleTree(t.Context(), ".", nil)

	got := make(map[string]string)
	var walk func(c *moduleConfig)
	walk = func(c *moduleConfig) {
		for _, child := range c.children {
			got[child.key] = child.path
			walk(child)
		}
	}
	walk(root)

	assert.Equal(t, map[string]string{
		"a":   "modules/a",
		"a.b": "modules/b",
	}, got)
}

func TestModuleIncludesItself(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		modules int
	}{
		{
			name: "directly",
			files: map[string]string{
				"main.tf": `
module "self" {
  source = "./"
}
`,
			},
			modules: 1,
		},
		{
			name: "through another module",
			files: map[string]string{
				"main.tf": `
module "a" {
  source = "./modules/a"
}
`,
				"modules/a/main.tf": `
module "b" {
  source = "../b"
}
`,
				"modules/b/main.tf": `
module "a" {
  source = "../a"
}
`,
			},
			modules: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(log.NewHandler(&buf, nil))

			parser := New(testutil.CreateFS(tt.files), "",
				OptionStopOnHCLError(true),
				OptionWithDownloads(false),
				OptionWithLogger(logger),
			)
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			modules, err := parser.EvaluateAll(t.Context())
			require.NoError(t, err)

			assert.Len(t, modules, tt.modules)
			assert.Contains(t, buf.String(), "Module includes itself")
		})
	}
}

func TestModuleSourceFromStaticValues(t *testing.T) {
	const moduleA = `resource "foo" "bar" {}`

	tests := []struct {
		name    string
		files   map[string]string
		opts    []Option
		env     map[string]string
		modules int
	}{
		{
			name: "variable default",
			files: map[string]string{
				"main.tf": `
variable "dir" {
  default = "./modules/a"
}

module "a" {
  source = var.dir
}
`,
				"modules/a/main.tf": moduleA,
			},
			modules: 2,
		},
		{
			name: "tfvars file",
			files: map[string]string{
				"main.tf": `
variable "dir" {}

module "a" {
  source = var.dir
}
`,
				"main.tfvars":       `dir = "./modules/a"`,
				"modules/a/main.tf": moduleA,
			},
			opts:    []Option{OptionWithTFVarsPaths("main.tfvars")},
			modules: 2,
		},
		{
			name: "environment variable",
			files: map[string]string{
				"main.tf": `
variable "dir" {}

module "a" {
  source = var.dir
}
`,
				"modules/a/main.tf": moduleA,
			},
			env:     map[string]string{"TF_VAR_dir": "./modules/a"},
			modules: 2,
		},
		{
			name: "locals in any order",
			files: map[string]string{
				"main.tf": `
locals {
  dir = "${local.base}/a"
}

locals {
  base = "./${var.root}"
}

variable "root" {
  default = "modules"
}

module "a" {
  source = local.dir
}
`,
				"modules/a/main.tf": moduleA,
			},
			modules: 2,
		},
		{
			name: "variable of a child module",
			files: map[string]string{
				"main.tf": `
module "a" {
  source = "./modules/a"
  dir    = "../b"
}
`,
				"modules/a/main.tf": `
variable "dir" {}

module "b" {
  source = var.dir
}
`,
				"modules/b/main.tf": moduleA,
			},
			modules: 3,
		},
		{
			name: "unknown variable of a child module",
			files: map[string]string{
				"main.tf": `
resource "foo" "bar" {}

module "a" {
  source = "./modules/a"
  dir    = foo.bar.id
}
`,
				"modules/a/main.tf": `
variable "dir" {}

module "b" {
  source = coalesce(var.dir, "../b")
}
`,
				"modules/b/main.tf": moduleA,
			},
			modules: 2,
		},
		{
			name: "resource attribute",
			files: map[string]string{
				"main.tf": `
resource "foo" "bar" {
  dir = "./modules/a"
}

module "a" {
  source = foo.bar.dir
}
`,
				"modules/a/main.tf": moduleA,
			},
			modules: 1,
		},
		{
			name: "local in a reference cycle",
			files: map[string]string{
				"main.tf": `
locals {
  a = local.b
  b = local.a
}

module "a" {
  source = local.a
}
`,
				"modules/a/main.tf": moduleA,
			},
			modules: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, val := range tt.env {
				t.Setenv(key, val)
			}

			opts := append([]Option{
				OptionStopOnHCLError(true),
				OptionWithDownloads(false),
			}, tt.opts...)
			parser := New(testutil.CreateFS(tt.files), "", opts...)
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			modules, err := parser.EvaluateAll(t.Context())
			require.NoError(t, err)
			assert.Len(t, modules, tt.modules)
		})
	}
}
