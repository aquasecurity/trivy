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

func Test_GetProperty_NestedPath(t *testing.T) {
	source := `---
Resources:
  MyResource:
    Type: AWS::S3::Bucket
    Properties:
      Outer:
        Inner:
          Value: inner-value
        Value: outer-value
        Empty:
      Unresolved: !Ref Missing
`
	files, err := parseFile(t, source, "cf.yaml")
	require.NoError(t, err)
	require.Len(t, files, 1)

	resource := files[0].GetResourceByLogicalID("MyResource")
	require.NotNil(t, resource)
	outer := resource.GetProperty("Outer")

	tests := []struct {
		name  string
		path  string
		check func(t *testing.T, prop *Property)
	}{
		{
			name: "existing value",
			path: "Outer.Inner.Value",
			check: func(t *testing.T, prop *Property) {
				require.Equal(t, "inner-value", prop.AsString())
			},
		},
		{
			name: "missing key in the middle of the path",
			path: "Outer.Missing.Value",
			check: func(t *testing.T, prop *Property) {
				require.True(t, prop.IsNil())
				require.Equal(t, outer.Metadata().Range(), prop.Metadata().Range())
			},
		},
		{
			name: "missing last key",
			path: "Outer.Missing",
			check: func(t *testing.T, prop *Property) {
				require.True(t, prop.IsNil())
				require.Equal(t, outer.Metadata().Range(), prop.Metadata().Range())
			},
		},
		{
			name: "empty value",
			path: "Outer.Empty",
			check: func(t *testing.T, prop *Property) {
				require.True(t, prop.IsNil())
			},
		},
		{
			name: "key inside empty value",
			path: "Outer.Empty.Value",
			check: func(t *testing.T, prop *Property) {
				require.True(t, prop.IsNil())
			},
		},
		{
			name: "key inside unresolved value",
			path: "Unresolved.Value",
			check: func(t *testing.T, prop *Property) {
				require.True(t, prop.IsUnresolved())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, resource.GetProperty(tt.path))
		})
	}
}
