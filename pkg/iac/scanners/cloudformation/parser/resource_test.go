package parser

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func Test_GetProperty_PropIsFunction(t *testing.T) {
	resource := Resource{
		typ: "AWS::S3::Bucket",
		properties: map[string]*Property{
			"BucketName": {
				Type:  cftypes.String,
				Value: "mybucket",
			},
			"VersioningConfiguration": {
				Type: cftypes.Map,
				Value: map[string]*Property{
					"Fn::If": {
						Type: cftypes.List,
						Value: []*Property{
							{
								Type:  cftypes.Bool,
								Value: false,
							},
							{
								Type: cftypes.Map,
								Value: map[string]*Property{
									"Status": {
										Type:  cftypes.String,
										Value: "Enabled",
									},
								},
							},
							{
								Type: cftypes.Map,
								Value: map[string]*Property{
									"Status": {
										Type:  cftypes.String,
										Value: "Suspended",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	prop := resource.GetProperty("VersioningConfiguration.Status")
	require.NotNil(t, prop)
	require.True(t, prop.IsString())
	require.Equal(t, "Suspended", prop.AsString())
}
