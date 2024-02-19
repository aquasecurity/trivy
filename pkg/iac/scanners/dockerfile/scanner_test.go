package dockerfile

import (
	"bytes"
	"context"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const DS006PolicyWithDockerfileSchema = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
	copies := docker.stage_copies[stage]

	copy := copies[_]
	flag := copy.Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage.Name, parts[1])
	args := parts[1]
	output := {
		"args": args,
		"cmd": copy,
	}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

	alias == current_alias

	allow = true
}

deny[res] {
	output := get_alias_from_copy[_]
	msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
	res := result.new(msg, output.cmd)
}
`

const DS006PolicyWithMyFancyDockerfileSchema = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["myfancydockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
copies := docker.stage_copies[stage]

copy := copies[_]
flag := copy.Flags[_]
contains(flag, "--from=")
parts := split(flag, "=")

is_alias_current_from_alias(stage.Name, parts[1])
args := parts[1]
output := {
"args": args,
"cmd": copy,
}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
current_name_lower := lower(current_name)
current_alias_lower := lower(current_alias)

#expecting stage name as "myimage:tag as dep"
[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

alias == current_alias

allow = true
}

deny[res] {
output := get_alias_from_copy[_]
msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
res := result.new(msg, output.cmd)
}
`

const DS006PolicyWithOldSchemaSelector = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
	copies := docker.stage_copies[stage]

	copy := copies[_]
	flag := copy.Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage.Name, parts[1])
	args := parts[1]
	output := {
		"args": args,
		"cmd": copy,
	}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

	alias == current_alias

	allow = true
}

deny[res] {
	output := get_alias_from_copy[_]
	msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
	res := result.new(msg, output.cmd)
}
`
const DS006LegacyWithOldStyleMetadata = `package builtin.dockerfile.DS006

__rego_metadata__ := {
	"id": "DS006",
	"avd_id": "AVD-DS-0006",
	"title": "COPY '--from' referring to the current image",
	"short_code": "no-self-referencing-copy-from",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"recommended_actions": "Change the '--from' so that it will not refer to itself",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	res := {
		"msg": "oh no",
		"filepath": "code/Dockerfile",
		"startline": 1,
		"endline": 1,
	}
}`

func Test_BasicScanLegacyRegoMetadata(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/Dockerfile": `FROM ubuntu
USER root
`,
		"/rules/rule.rego": DS006LegacyWithOldStyleMetadata,
	})

	scanner := NewScanner(options.ScannerWithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]
	metadata := failure.Metadata()
	assert.Equal(t, 1, metadata.Range().GetStartLine())
	assert.Equal(t, 1, metadata.Range().GetEndLine())
	assert.Equal(t, "code/Dockerfile", metadata.Range().GetFilename())

	assert.Equal(
		t,
		scan.Rule{
			AVDID:          "AVD-DS-0006",
			Aliases:        []string{"DS006"},
			ShortCode:      "no-self-referencing-copy-from",
			Summary:        "COPY '--from' referring to the current image",
			Explanation:    "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
			Impact:         "",
			Resolution:     "Change the '--from' so that it will not refer to itself",
			Provider:       "dockerfile",
			Service:        "general",
			Links:          []string{"https://docs.docker.com/develop/develop-images/multistage-build/"},
			Severity:       "CRITICAL",
			Terraform:      &scan.EngineMetadata{},
			CloudFormation: &scan.EngineMetadata{},
			CustomChecks: scan.CustomChecks{
				Terraform: (*scan.TerraformCustomCheck)(nil)},
			RegoPackage: "data.builtin.dockerfile.DS006",
			Frameworks:  map[framework.Framework][]string{},
		},
		results.GetFailed()[0].Rule(),
	)

	actualCode, err := results.GetFailed()[0].GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     1,
			Content:    "FROM ubuntu",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_BasicScanNewRegoMetadata(t *testing.T) {
	var testCases = []struct {
		name                    string
		inputRegoPolicy         string
		expectedError           string
		expectedInputTraceLogs  string
		expectedOutputTraceLogs string
	}{
		{
			name:            "old schema selector schema.input",
			inputRegoPolicy: DS006PolicyWithOldSchemaSelector,
			expectedInputTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT
`,
			expectedOutputTraceLogs: `REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "parent": null,
            "resource": "",
            "sourceprefix": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name:            "new schema selector schema.dockerfile",
			inputRegoPolicy: DS006PolicyWithDockerfileSchema,
			expectedInputTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT
`,
			expectedOutputTraceLogs: `REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "parent": null,
            "resource": "",
            "sourceprefix": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name:            "new schema selector with custom schema.myfancydockerfile",
			inputRegoPolicy: DS006PolicyWithMyFancyDockerfileSchema,
			expectedInputTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT
`,
			expectedOutputTraceLogs: `REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "parent": null,
            "resource": "",
            "sourceprefix": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name: "new schema selector but invalid",
			inputRegoPolicy: `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["spooky-schema"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006
deny[res]{
res := true
}`,
			expectedError: `1 error occurred: rules/rule.rego:12: rego_type_error: undefined schema: schema["spooky-schema"]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			regoMap := make(map[string]string)
			libs, err := rego.LoadEmbeddedLibraries()
			require.NoError(t, err)
			for name, library := range libs {
				regoMap["/rules/"+name] = library.String()
			}
			regoMap["/code/Dockerfile"] = `FROM golang:1.7.3 as dep
COPY --from=dep /binary /`
			regoMap["/rules/rule.rego"] = tc.inputRegoPolicy
			regoMap["/rules/schemas/myfancydockerfile.json"] = string(schemas.Dockerfile) // just use the same for testing
			fs := testutil.CreateFS(t, regoMap)

			var traceBuf bytes.Buffer
			var debugBuf bytes.Buffer

			scanner := NewScanner(
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithTrace(&traceBuf),
				options.ScannerWithDebug(&debugBuf),
				options.ScannerWithRegoErrorLimits(0),
			)

			results, err := scanner.ScanFS(context.TODO(), fs, "code")
			if tc.expectedError != "" && err != nil {
				require.Equal(t, tc.expectedError, err.Error(), tc.name)
			} else {
				require.NoError(t, err)
				require.Len(t, results.GetFailed(), 1)

				failure := results.GetFailed()[0]
				metadata := failure.Metadata()
				assert.Equal(t, 2, metadata.Range().GetStartLine())
				assert.Equal(t, 2, metadata.Range().GetEndLine())
				assert.Equal(t, "code/Dockerfile", metadata.Range().GetFilename())

				assert.Equal(
					t,
					scan.Rule{
						AVDID:          "AVD-DS-0006",
						Aliases:        []string{"DS006"},
						ShortCode:      "no-self-referencing-copy-from",
						Summary:        "COPY '--from' referring to the current image",
						Explanation:    "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
						Impact:         "",
						Resolution:     "Change the '--from' so that it will not refer to itself",
						Provider:       "dockerfile",
						Service:        "general",
						Links:          []string{"https://docs.docker.com/develop/develop-images/multistage-build/"},
						Severity:       "CRITICAL",
						Terraform:      &scan.EngineMetadata{},
						CloudFormation: &scan.EngineMetadata{},
						CustomChecks: scan.CustomChecks{
							Terraform: (*scan.TerraformCustomCheck)(nil)},
						RegoPackage: "data.builtin.dockerfile.DS006",
						Frameworks:  map[framework.Framework][]string{},
					},
					results.GetFailed()[0].Rule(),
				)

				actualCode, err := results.GetFailed()[0].GetCode()
				require.NoError(t, err)
				for i := range actualCode.Lines {
					actualCode.Lines[i].Highlighted = ""
				}
				assert.Equal(t, []scan.Line{
					{
						Number:     2,
						Content:    "COPY --from=dep /binary /",
						IsCause:    true,
						FirstCause: true,
						LastCause:  true,
						Annotation: "",
					},
				}, actualCode.Lines)

				// assert logs
				assert.Contains(t, traceBuf.String(), tc.expectedInputTraceLogs, traceBuf.String())
				assert.Contains(t, traceBuf.String(), tc.expectedOutputTraceLogs, traceBuf.String())
			}
		})
	}

}
