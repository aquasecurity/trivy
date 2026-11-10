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

	root := parser.loadModuleTree(t.Context(), ".")

	got := make(map[string]string)
	var walk func(c *moduleConfig)
	walk = func(c *moduleConfig) {
		for _, child := range c.children {
			got[child.key] = child.parser.modulePath
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
