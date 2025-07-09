package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_clearURI(t *testing.T) {
	test := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "https",
			uri:  "bitbucket.org/hashicorp/terraform-consul-aws",
			want: "bitbucket.org/hashicorp/terraform-consul-aws",
		},
		{
			name: "github",
			uri:  "git@github.com:terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.2.0/main.tf",
			want: "github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf",
		},
		{
			name: "git",
			uri:  "git::https://example.com/storage.git?ref=51d462976d84fdea54b47d80dcabbf680badcdb8",
			want: "https://example.com/storage?ref=51d462976d84fdea54b47d80dcabbf680badcdb8",
		},
		{
			name: "git ssh",
			uri:  "git::ssh://username@example.com/storage.git",
			want: "example.com/storage",
		},
		{
			name: "hg",
			uri:  "hg::http://example.com/vpc.hg?ref=v1.2.0",
			want: "http://example.com/vpc?ref=v1.2.0",
		},
		{
			name: "s3",
			uri:  "s3::https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip",
			want: "https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip",
		},
		{
			name: "gcs",
			uri:  "gcs::https://www.googleapis.com/storage/v1/modules/foomodule.zip",
			want: "https://www.googleapis.com/storage/v1/modules/foomodule.zip",
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			got := clearURI(tt.uri)
			require.Equal(t, tt.want, got)
			require.NotNil(t, toUri(got))
		})
	}
}

func TestMakePropertiesMarshal(t *testing.T) {
	tests := []struct {
		name      string
		title     string
		severity  string
		cvssScore string
		cvssData  map[string]any
		expected  string
	}{
		{
			name:      "no CVSS data",
			title:     "test",
			severity:  "HIGH",
			cvssScore: "5.0",
			cvssData:  make(map[string]any),
			expected: `{
				"precision": "very-high",
				"security-severity": "5.0",
				"tags": ["test", "security", "HIGH"]
			}`,
		},
		{
			name:      "only CVSS v2",
			title:     "test",
			severity:  "CRITICAL",
			cvssScore: "4.0",
			cvssData: map[string]any{
				"cvssv2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
				"cvssv2_score":  5.0,
			},
			expected: `{
				"cvssv2_score": 5,
				"cvssv2_vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
				"precision": "very-high",
				"security-severity": "4.0",
				"tags": ["test", "security", "CRITICAL"]
			}`,
		},
		{
			name:      "only CVSS v3",
			title:     "test",
			severity:  "CRITICAL",
			cvssScore: "9.8",
			cvssData: map[string]any{
				"cvssv3_vector":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cvssv3_baseScore": 9.8,
			},
			expected: `{
				"cvssv3_baseScore": 9.8,
				"cvssv3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"precision": "very-high",
				"security-severity": "9.8",
				"tags": ["test", "security", "CRITICAL"]
			}`,
		},
		{
			name:      "only CVSS v4",
			title:     "test",
			severity:  "LOW",
			cvssScore: "3.5",
			cvssData: map[string]any{
				"cvssv40_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				"cvssv40_score":  3.5,
			},
			expected: `{
				"cvssv40_score": 3.5,
				"cvssv40_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				"precision": "very-high",
				"security-severity": "3.5",
				"tags": ["test", "security", "LOW"]
			}`,
		},
		{
			name:      "all CVSS versions",
			title:     "test",
			severity:  "HIGH",
			cvssScore: "8.1",
			cvssData: map[string]any{
				"cvssv2_vector":    "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				"cvssv2_score":     7.5,
				"cvssv3_vector":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cvssv3_baseScore": 9.8,
				"cvssv40_vector":   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				"cvssv40_score":    9.3,
			},
			expected: `{
				"cvssv2_score": 7.5,
				"cvssv2_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
				"cvssv3_baseScore": 9.8,
				"cvssv3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cvssv40_score": 9.3,
				"cvssv40_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
				"precision": "very-high",
				"security-severity": "8.1",
				"tags": ["test", "security", "HIGH"]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toProperties(tt.title, tt.severity, tt.cvssScore, tt.cvssData)

			actualJSON, err := json.Marshal(result)
			require.NoError(t, err)

			var expectedJSON bytes.Buffer
			err = json.Compact(&expectedJSON, []byte(tt.expected))
			require.NoError(t, err)
			assert.JSONEq(t, expectedJSON.String(), string(actualJSON))
		})
	}
}
