package parser

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/log"
)

func Test_TFVarsFile(t *testing.T) {
	t.Run("tfvars file", func(t *testing.T) {
		fs := testutil.CreateFS(map[string]string{
			"test.tfvars": `instance_type = "t2.large"`,
		})

		vars, err := loadTFVars(fs, []string{"test.tfvars"})
		require.NoError(t, err)
		assert.Equal(t, "t2.large", vars["instance_type"].AsString())
	})

	t.Run("tfvars json file", func(t *testing.T) {
		fs := testutil.CreateFS(map[string]string{
			"test.tfvars.json": `{
  "variable": {
    "foo": {
      "default": "bar"
    },
    "baz": "qux"
  },
  "foo2": true,
  "foo3": 3
}`,
		})

		vars, err := loadTFVars(fs, []string{"test.tfvars.json"})
		require.NoError(t, err)
		assert.Equal(t, "bar", vars["variable"].GetAttr("foo").GetAttr("default").AsString())
		assert.Equal(t, "qux", vars["variable"].GetAttr("baz").AsString())
		assert.True(t, vars["foo2"].True())
		assert.True(t, vars["foo3"].Equals(cty.NumberIntVal(3)).True())
	})
}

func variableBlocks(t *testing.T, src string) terraform.Blocks {
	t.Helper()

	parser := New(testutil.CreateFS(map[string]string{"main.tf": src}), "")
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	blocks, _, err := parser.readBlocks(parser.files)
	require.NoError(t, err)
	return blocks
}

func Test_LoadEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		variable    string
		env         string
		want        cty.Value
		wantSkipped bool
	}{
		{
			name:     "map(string) with = in the value",
			variable: "type = map(string)",
			env:      `{env="prod"}`,
			want:     cty.ObjectVal(map[string]cty.Value{"env": cty.StringVal("prod")}),
		},
		{
			name:     "list(number)",
			variable: "type = list(number)",
			env:      "[1, 2]",
			want:     cty.TupleVal([]cty.Value{cty.NumberIntVal(1), cty.NumberIntVal(2)}),
		},
		{
			name:     "object",
			variable: "type = object({ a = number })",
			env:      "{a=1}",
			want:     cty.ObjectVal(map[string]cty.Value{"a": cty.NumberIntVal(1)}),
		},
		{
			name:     "any is parsed as HCL",
			variable: "type = any",
			env:      `["a","b"]`,
			want:     cty.TupleVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}),
		},
		{
			name:     "variable without type stays a literal",
			variable: "",
			env:      "{a=1}",
			want:     cty.StringVal("{a=1}"),
		},
		{
			name:     "string that looks like HCL stays a string",
			variable: "type = string",
			env:      `["a"]`,
			want:     cty.StringVal(`["a"]`),
		},
		{
			name:     "string keeps = in the value",
			variable: "type = string",
			env:      "a=b",
			want:     cty.StringVal("a=b"),
		},
		{
			name:     "number stays a literal",
			variable: "type = number",
			env:      "5",
			want:     cty.StringVal("5"),
		},
		{
			name:        "unparseable value is skipped",
			variable:    "type = list(string)",
			env:         "[oops",
			wantSkipped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := variableBlocks(t, "variable \"x\" {\n"+tt.variable+"\n}\n")
			t.Setenv("TF_VAR_x", tt.env)

			var buf bytes.Buffer
			logger := slog.New(log.NewHandler(&buf, nil))

			vars := loadEnvVars(logger, blocks)

			got, ok := vars["x"]
			if tt.wantSkipped {
				assert.False(t, ok, "variable should be skipped")
				assert.Contains(t, buf.String(), "Ignoring TF_VAR environment variable")
				return
			}

			require.True(t, ok)
			assert.True(t, tt.want.RawEquals(got), "want %#v, got %#v", tt.want, got)
			assert.Empty(t, buf.String())
		})
	}
}

func evalResourceValue(t *testing.T, files map[string]string, opts ...Option) cty.Value {
	t.Helper()

	opts = append([]Option{OptionStopOnHCLError(true)}, opts...)

	parser := New(testutil.CreateFS(files), "", opts...)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)

	resources := modules[0].GetResourcesByType("something")
	require.Len(t, resources, 1)

	attr := resources[0].GetAttribute("value")
	require.NotNil(t, attr)
	require.True(t, attr.IsResolvable())
	return attr.Value()
}

func Test_TFVarsEnvEndToEnd(t *testing.T) {
	const tagsTF = `
variable "tags" {
  type    = map(string)
  default = {}
}

resource "something" "blah" {
  value = var.tags
}
`

	t.Run("map from environment variable", func(t *testing.T) {
		t.Setenv("TF_VAR_tags", `{env="prod"}`)

		got := evalResourceValue(t, map[string]string{"main.tf": tagsTF})
		require.True(t, got.Type().IsMapType(), "var.tags must become a map, got %s", got.Type().FriendlyName())
		assert.Equal(t, "prod", got.AsValueMap()["env"].AsString())
	})

	t.Run("invalid value falls back to the default", func(t *testing.T) {
		t.Setenv("TF_VAR_tags", `[oops`)

		got := evalResourceValue(t, map[string]string{
			"main.tf": `
variable "tags" {
  type    = map(string)
  default = { env = "default" }
}

resource "something" "blah" {
  value = var.tags
}
`,
		})
		require.True(t, got.Type().IsMapType())
		assert.Equal(t, "default", got.AsValueMap()["env"].AsString())
	})

	t.Run("tfvars file overrides environment variable", func(t *testing.T) {
		t.Setenv("TF_VAR_tags", `{env="prod"}`)

		got := evalResourceValue(t, map[string]string{
			"main.tf":     tagsTF,
			"main.tfvars": `tags = { env = "dev" }`,
		}, OptionWithTFVarsPaths("main.tfvars"))
		require.True(t, got.Type().IsMapType())
		assert.Equal(t, "dev", got.AsValueMap()["env"].AsString())
	})
}
