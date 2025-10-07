package dockerfile_test

import (
	"bytes"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rego/schemas"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile"
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
	fs := testutil.CreateFS(map[string]string{
		"/code/Dockerfile": `FROM ubuntu
USER root
`,
		"/rules/rule.rego": DS006LegacyWithOldStyleMetadata,
	})

	scanner := dockerfile.NewScanner(rego.WithPolicyDirs("rules"))

	results, err := scanner.ScanFS(t.Context(), fs, "code")
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
			ID:             "DS006",
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
			RegoPackage:    "data.builtin.dockerfile.DS006",
			Frameworks: map[framework.Framework][]string{
				framework.Default: {},
			},
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
			expectedError: "could not find schema \"spooky-schema\"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fsysMap := make(map[string]string)
			fsysMap["/code/Dockerfile"] = `FROM golang:1.7.3 as dep
COPY --from=dep /binary /`
			fsysMap["/rules/rule.rego"] = tc.inputRegoPolicy
			fsysMap["/rules/schemas/myfancydockerfile.json"] = string(schemas.Dockerfile) // just use the same for testing
			fsys := testutil.CreateFS(fsysMap)

			var traceBuf bytes.Buffer

			scanner := dockerfile.NewScanner(
				rego.WithPolicyDirs("rules"),
				rego.WithEmbeddedLibraries(true),
				rego.WithTrace(&traceBuf),
				rego.WithRegoErrorLimits(0),
			)

			results, err := scanner.ScanFS(t.Context(), fsys, "code")
			if tc.expectedError != "" && err != nil {
				require.ErrorContainsf(t, err, tc.expectedError, tc.name)
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
						ID:             "DS006",
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
						RegoPackage:    "data.builtin.dockerfile.DS006",
						Frameworks: map[framework.Framework][]string{
							framework.Default: {},
						},
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

func Test_IgnoreByInlineComments(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		expected bool
	}{
		{
			name: "without ignore rule",
			src: `FROM scratch
MAINTAINER moby@example.com`,
			expected: true,
		},
		{
			name: "with ignore rule",
			src: `FROM scratch
# trivy:ignore:USER-TEST-0001
MAINTAINER moby@example.com`,
			expected: false,
		},
	}

	check := `# METADATA
# title: test
# schemas:
# - input: schema["dockerfile"]
# custom:
#   avd_id: USER-TEST-0001
#   short_code: maintainer-deprecated
#   input:
#     selector:
#     - type: dockerfile
package user.test0001

import rego.v1

get_maintainer contains cmd if {
	cmd := input.Stages[_].Commands[_]
	cmd.Cmd == "maintainer"
}

deny contains res if {
	cmd := get_maintainer[_]
	msg := sprintf("MAINTAINER should not be used: 'MAINTAINER %s'", [cmd.Value[0]])
	res := result.new(msg, cmd)
}
`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"Dockerfile": &fstest.MapFile{Data: []byte(tt.src)},
			}

			scanner := dockerfile.NewScanner(
				rego.WithPolicyReader(strings.NewReader(check)),
				rego.WithPolicyNamespaces("user"),
				rego.WithEmbeddedLibraries(true),
				rego.WithRegoErrorLimits(0),
			)
			results, err := scanner.ScanFS(t.Context(), fsys, ".")
			require.NoError(t, err)
			if tt.expected {
				testutil.AssertRuleFound(t, "dockerfile-general-maintainer-deprecated", results, "")
			} else {
				testutil.AssertRuleNotFailed(t, "dockerfile-general-maintainer-deprecated", results, "")
			}
		})
	}
}
