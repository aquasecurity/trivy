package state

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_RegoConversion(t *testing.T) {
	s := State{
		AWS: aws.AWS{
			S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: iacTypes.NewMetadata(
							iacTypes.NewRange("main.tf", 2, 4, "", nil),
							"aws_s3_bucket.example",
						),
						Name: iacTypes.String("my-bucket", iacTypes.NewMetadata(
							iacTypes.NewRange("main.tf", 3, 3, "", nil),
							"aws_s3_bucket.example.bucket",
						)),
					},
				},
			},
		},
	}
	converted := s.ToRego()
	assert.Equal(t, map[string]any{
		"aws": map[string]any{
			"s3": map[string]any{
				"buckets": []any{
					map[string]any{
						"__defsec_metadata": map[string]any{
							"resource":     "aws_s3_bucket.example",
							"sourceprefix": "",
							"filepath":     "main.tf",
							"startline":    2,
							"endline":      4,
							"managed":      true,
							"unresolvable": false,
							"explicit":     false,
							"fskey":        "",
						},
						"name": map[string]any{
							"resource":     "aws_s3_bucket.example.bucket",
							"sourceprefix": "",
							"filepath":     "main.tf",
							"startline":    3,
							"endline":      3,
							"value":        "my-bucket",
							"managed":      true,
							"unresolvable": false,
							"explicit":     false,
							"fskey":        "",
						},
					},
				},
			},
		},
	}, converted)
}

func Test_JSONPersistenceOfData(t *testing.T) {
	s := State{
		AWS: aws.AWS{
			S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: iacTypes.NewMetadata(
							iacTypes.NewRange("main.tf", 2, 4, "", nil),
							"aws_s3_bucket.example",
						),
						Name: iacTypes.String("my-bucket", iacTypes.NewMetadata(
							iacTypes.NewRange("main.tf", 3, 3, "", nil),
							"aws_s3_bucket.example.bucket",
						)),
					},
				},
			},
		},
	}
	data, err := json.Marshal(s)
	require.NoError(t, err)

	var restored State
	require.NoError(t, json.Unmarshal(data, &restored))

	assert.Equal(t, s, restored)
}
