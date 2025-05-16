package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func Test_UpdateStaticMetadata(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		sm := StaticMetadata{
			ID:                      "i",
			AVDID:                   "a",
			Title:                   "t",
			ShortCode:               "sc",
			Aliases:                 []string{"a", "b", "c"},
			Description:             "d",
			Severity:                "s",
			RecommendedActions:      "ra",
			PrimaryURL:              "pu",
			References:              []string{"r"},
			Package:                 "pkg",
			Provider:                "pr",
			Service:                 "srvc",
			Library:                 false,
			MinimumSupportedVersion: "v1.2.3",
		}

		require.NoError(t, sm.populate(
			map[string]any{
				"id":                  "i_n",
				"avd_id":              "a_n",
				"title":               "t_n",
				"short_code":          "sc_n",
				"aliases":             []any{"a_n", "b_n", "c_n"},
				"description":         "d_n",
				"service":             "srvc_n",
				"provider":            "pr_n",
				"recommended_actions": "ra_n",
				"severity":            "s_n",
				"library":             true,
				"url":                 "r_n",
				"frameworks": map[string]any{
					"all": []any{"aa"},
				},
				"minimum_supported_version": "v1.2.3",
			},
		))

		expected := StaticMetadata{
			ID:                 "i_n",
			AVDID:              "a_n",
			Title:              "t_n",
			ShortCode:          "sc_n",
			Aliases:            []string{"a", "b", "c", "a_n", "b_n", "c_n"},
			Description:        "d_n",
			Severity:           "S_N",
			RecommendedActions: "ra_n",
			PrimaryURL:         "pu",
			MinimumSupportedVersion: "v1.2.3",
			References:         []string{"r", "r_n"},
			Package:            "pkg",
			Provider:           "pr_n",
			Service:            "srvc_n",
			Library:            true,
			Frameworks: map[framework.Framework][]string{
				framework.ALL: {"aa"},
			},
			CloudFormation: &scan.EngineMetadata{},
			Terraform:      &scan.EngineMetadata{},
		}

		assert.Equal(t, expected, sm)
	})

	t.Run("related resources are a map", func(t *testing.T) {
		sm := StaticMetadata{
			References: []string{"r"},
		}
		require.NoError(t, sm.populate(map[string]any{
			"related_resources": []map[string]any{
				{
					"ref": "r1_n",
				},
				{
					"ref": "r2_n",
				},
			},
		}))

		expected := StaticMetadata{
			References:     []string{"r", "r1_n", "r2_n"},
			CloudFormation: &scan.EngineMetadata{},
			Terraform:      &scan.EngineMetadata{},
			Frameworks:     make(map[framework.Framework][]string),
		}

		assert.Equal(t, expected, sm)
	})

	t.Run("related resources are a string", func(t *testing.T) {
		sm := StaticMetadata{
			References: []string{"r"},
		}
		require.NoError(t, sm.populate(map[string]any{
			"related_resources": []string{"r1_n", "r2_n"},
		}))

		expected := StaticMetadata{
			References:     []string{"r", "r1_n", "r2_n"},
			CloudFormation: &scan.EngineMetadata{},
			Terraform:      &scan.EngineMetadata{},
			Frameworks:     make(map[framework.Framework][]string),
		}

		assert.Equal(t, expected, sm)
	})

	t.Run("check is deprecated", func(t *testing.T) {
		sm := StaticMetadata{
			Deprecated: false,
		}
		require.NoError(t, sm.populate(map[string]any{
			"deprecated": true,
		}))

		expected := StaticMetadata{
			Deprecated:     true,
			CloudFormation: &scan.EngineMetadata{},
			Terraform:      &scan.EngineMetadata{},
			Frameworks:     make(map[framework.Framework][]string),
		}

		assert.Equal(t, expected, sm)
	})

	t.Run("frameworks is not initialized", func(t *testing.T) {
		sm := StaticMetadata{}
		err := sm.populate(map[string]any{
			"frameworks": map[string]any{"all": []any{"a", "b", "c"}},
		})
		require.NoError(t, err)
	})
}

func Test_NewEngineMetadata(t *testing.T) {
	inputSchema := map[string]any{
		"terraform": map[string]any{
			"good_examples": `resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }`,

			"links": "https://avd.aquasec.com/avd/183",
		},
		"cloud_formation": map[string]any{
			"good_examples": `---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"`,
			"links": []any{"https://avd.aquasec.com/avd/183"},
		},
	}

	var testCases = []struct {
		schema string
		want   *scan.EngineMetadata
	}{
		{
			schema: "terraform",
			want: &scan.EngineMetadata{
				GoodExamples: []string{
					`resource "aws_cloudtrail" "good_example" {
   is_multi_region_trail = true
 
   event_selector {
     read_write_type           = "All"
     include_management_events = true
 
     data_resource {
       type = "AWS::S3::Object"
       values = ["${data.aws_s3_bucket.important-bucket.arn}/"]
     }
   }
 }`,
				},
				Links: []string{"https://avd.aquasec.com/avd/183"},
			},
		},
		{
			schema: "cloud_formation",
			want: &scan.EngineMetadata{
				GoodExamples: []string{
					`---
Resources:
  GoodExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"`,
				},
				Links: []string{"https://avd.aquasec.com/avd/183"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.schema, func(t *testing.T) {
			em, err := NewEngineMetadata(tc.schema, inputSchema)
			require.NoError(t, err)
			assert.Equal(t, tc.want, em)
		})
	}
}

func TestMetadataFromAnnotations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *StaticMetadata
		wantErr  string
	}{
		{
			name: "happy",
			input: `# METADATA
# title: test
# custom:
#   id: test-001
#   avd_id: test-001
#   severity: LOW
#   minimum_supported_version: 1.2.3
#   input:
#     selector:
#     - type: yaml
package user.test
`,
			expected: &StaticMetadata{
				Title:    "test",
				ID:       "test-001",
				AVDID:    "test-001",
				Severity: "LOW",
				InputOptions: InputOptions{
					Selectors: []Selector{
						{
							Type: "yaml",
						},
					},
				},
				MinimumSupportedVersion: "1.2.3",
				Package: "data.user.test",
				Frameworks: map[framework.Framework][]string{
					"default": {},
				},
				Terraform:      &scan.EngineMetadata{},
				CloudFormation: &scan.EngineMetadata{},
			},
		},
		{
			name: "without custom",
			input: `# METADATA
# title: test
package user.test
`,
			expected: &StaticMetadata{
				Title:    "test",
				ID:       "N/A",
				Severity: "UNKNOWN",
				Package:  "data.user.test",
				Frameworks: map[framework.Framework][]string{
					"default": {},
				},
				Terraform:      &scan.EngineMetadata{},
				CloudFormation: &scan.EngineMetadata{},
			},
		},
		{
			name:     "without annotations",
			input:    `package user.test`,
			expected: nil,
		},
		{
			name: "invalid input field",
			input: `# METADATA
# custom:
#  input: bad
package user.test`,
			wantErr: "input is not an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, err := ast.ParseModuleWithOpts("test.rego", tt.input, ast.ParserOptions{
				ProcessAnnotation: true,
			})
			require.NoError(t, err)

			metadata, err := MetadataFromAnnotations(module)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.expected, metadata)
		})
	}
}
