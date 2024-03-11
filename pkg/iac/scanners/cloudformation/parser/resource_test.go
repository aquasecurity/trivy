package parser

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/stretchr/testify/require"
)

func Test_GetProperty_PropIsFunction(t *testing.T) {
	resource := Resource{
		Inner: ResourceInner{
			Type: "AWS::S3::Bucket",
			Properties: map[string]*Property{
				"BucketName": {
					Inner: PropertyInner{
						Type:  cftypes.String,
						Value: "mybucket",
					},
				},
				"VersioningConfiguration": {
					Inner: PropertyInner{
						Type: cftypes.Map,
						Value: map[string]*Property{
							"Fn::If": {
								Inner: PropertyInner{
									Type: cftypes.List,
									Value: []*Property{
										{
											Inner: PropertyInner{
												Type:  cftypes.Bool,
												Value: false,
											},
										},
										{
											Inner: PropertyInner{
												Type: cftypes.Map,
												Value: map[string]*Property{
													"Status": {
														Inner: PropertyInner{
															Type:  cftypes.String,
															Value: "Enabled",
														},
													},
												},
											},
										},
										{
											Inner: PropertyInner{
												Type: cftypes.Map,
												Value: map[string]*Property{
													"Status": {
														Inner: PropertyInner{
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
