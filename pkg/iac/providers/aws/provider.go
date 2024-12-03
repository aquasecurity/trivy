package aws

import "github.com/aquasecurity/trivy/pkg/iac/types"

type TerraformProvider struct {
	Metadata types.Metadata
	// generic fields
	Alias   types.StringValue
	Version types.StringValue

	// provider specific fields
	AccessKey                      types.StringValue
	AllowedAccountsIDs             types.StringValueList
	AssumeRole                     AssumeRole
	AssumeRoleWithWebIdentity      AssumeRoleWithWebIdentity
	CustomCABundle                 types.StringValue
	DefaultTags                    DefaultTags
	EC2MetadataServiceEndpoint     types.StringValue
	EC2MetadataServiceEndpointMode types.StringValue
	Endpoints                      types.MapValue
	ForbiddenAccountIDs            types.StringValueList
	HttpProxy                      types.StringValue
	IgnoreTags                     IgnoreTags
	Insecure                       types.BoolValue
	MaxRetries                     types.IntValue
	Profile                        types.StringValue
	Region                         types.StringValue
	RetryMode                      types.StringValue
	S3UsePathStyle                 types.BoolValue
	S3USEast1RegionalEndpoint      types.StringValue
	SecretKey                      types.StringValue
	SharedConfigFiles              types.StringValueList
	SharedCredentialsFiles         types.StringValueList
	SkipCredentialsValidation      types.BoolValue
	SkipMetadataAPICheck           types.BoolValue
	SkipRegionValidation           types.BoolValue
	SkipRequestingAccountID        types.BoolValue
	STSRegion                      types.StringValue
	Token                          types.StringValue
	UseDualstackEndpoint           types.BoolValue
	UseFIPSEndpoint                types.BoolValue
}

type AssumeRole struct {
	Metadata          types.Metadata
	Duration          types.StringValue
	ExternalID        types.StringValue
	Policy            types.StringValue
	PolicyARNs        types.StringValueList
	RoleARN           types.StringValue
	SessionName       types.StringValue
	SourceIdentity    types.StringValue
	Tags              types.MapValue
	TransitiveTagKeys types.StringValueList
}

type AssumeRoleWithWebIdentity struct {
	Metadata             types.Metadata
	Duration             types.StringValue
	Policy               types.StringValue
	PolicyARNs           types.StringValueList
	RoleARN              types.StringValue
	SessionName          types.StringValue
	WebIdentityToken     types.StringValue
	WebIdentityTokenFile types.StringValue
}

type IgnoreTags struct {
	Metadata    types.Metadata
	Keys        types.StringValueList
	KeyPrefixes types.StringValueList
}

type DefaultTags struct {
	Metadata types.Metadata
	Tags     types.MapValue
}
