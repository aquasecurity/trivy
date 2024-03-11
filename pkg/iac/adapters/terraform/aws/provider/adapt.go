package provider

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	defaultMaxRetires       = 25
	defaultSharedConfigFile = "~/.aws/config"
	//#nosec G101 -- False positive
	defaultSharedCredentialsFile = "~/.aws/credentials"
)

func Adapt(modules terraform.Modules) []aws.TerraformProvider {
	return adaptProviders(modules)
}

func adaptProviders(modules terraform.Modules) []aws.TerraformProvider {
	var providers []aws.TerraformProvider
	for _, providerBlock := range modules.GetBlocks().OfType("provider") {
		if providerBlock.Label() == "aws" {
			providers = append(providers, adaptProvider(providerBlock))
		}
	}

	return providers
}

func adaptProvider(b *terraform.Block) aws.TerraformProvider {
	return aws.TerraformProvider{
		Metadata:                       b.GetMetadata(),
		Alias:                          getStringAttrValue("alias", b),
		Version:                        getStringAttrValue("version", b),
		AccessKey:                      getStringAttrValue("access_key", b),
		AllowedAccountsIDs:             b.GetAttribute("allowed_account_ids").AsStringValueSliceOrEmpty(),
		AssumeRole:                     adaptAssumeRole(b),
		AssumeRoleWithWebIdentity:      adaptAssumeRoleWithWebIdentity(b),
		CustomCABundle:                 getStringAttrValue("custom_ca_bundle", b),
		DefaultTags:                    adaptDefaultTags(b),
		EC2MetadataServiceEndpoint:     getStringAttrValue("ec2_metadata_service_endpoint", b),
		EC2MetadataServiceEndpointMode: getStringAttrValue("ec2_metadata_service_endpoint_mode", b),
		Endpoints:                      adaptEndpoints(b),
		ForbiddenAccountIDs:            b.GetAttribute("forbidden_account_ids").AsStringValueSliceOrEmpty(),
		HttpProxy:                      getStringAttrValue("http_proxy", b),
		IgnoreTags:                     adaptIgnoreTags(b),
		Insecure:                       b.GetAttribute("insecure").AsBoolValueOrDefault(false, b),
		MaxRetries:                     b.GetAttribute("max_retries").AsIntValueOrDefault(defaultMaxRetires, b),
		Profile:                        getStringAttrValue("profile", b),
		Region:                         getStringAttrValue("region", b),
		RetryMode:                      getStringAttrValue("retry_mode", b),
		S3UsePathStyle:                 b.GetAttribute("s3_use_path_style").AsBoolValueOrDefault(false, b),
		S3USEast1RegionalEndpoint:      getStringAttrValue("s3_us_east_1_regional_endpoint", b),
		SecretKey:                      getStringAttrValue("secret_key", b),
		SharedConfigFiles:              b.GetAttribute("shared_config_files").AsStringValuesOrDefault(b, defaultSharedConfigFile),
		SharedCredentialsFiles:         b.GetAttribute("shared_credentials_files").AsStringValuesOrDefault(b, defaultSharedCredentialsFile),
		SkipCredentialsValidation:      b.GetAttribute("skip_credentials_validation").AsBoolValueOrDefault(false, b),
		SkipMetadataAPICheck:           b.GetAttribute("skip_metadata_api_check").AsBoolValueOrDefault(false, b),
		SkipRegionValidation:           b.GetAttribute("skip_region_validation").AsBoolValueOrDefault(false, b),
		SkipRequestingAccountID:        b.GetAttribute("skip_requesting_account_id").AsBoolValueOrDefault(false, b),
		STSRegion:                      getStringAttrValue("sts_region", b),
		Token:                          getStringAttrValue("token", b),
		UseDualstackEndpoint:           b.GetAttribute("use_dualstack_endpoint").AsBoolValueOrDefault(false, b),
		UseFIPSEndpoint:                b.GetAttribute("use_fips_endpoint").AsBoolValueOrDefault(false, b),
	}
}

func adaptAssumeRole(p *terraform.Block) aws.AssumeRole {
	assumeRoleBlock := p.GetBlock("assume_role")

	if assumeRoleBlock.IsNil() {
		return aws.AssumeRole{
			Metadata:       p.GetMetadata(),
			Duration:       types.StringDefault("", p.GetMetadata()),
			ExternalID:     types.StringDefault("", p.GetMetadata()),
			Policy:         types.StringDefault("", p.GetMetadata()),
			RoleARN:        types.StringDefault("", p.GetMetadata()),
			SessionName:    types.StringDefault("", p.GetMetadata()),
			SourceIdentity: types.StringDefault("", p.GetMetadata()),
		}
	}

	return aws.AssumeRole{
		Metadata:          assumeRoleBlock.GetMetadata(),
		Duration:          getStringAttrValue("duration", p),
		ExternalID:        getStringAttrValue("external_id", p),
		Policy:            getStringAttrValue("policy", p),
		PolicyARNs:        p.GetAttribute("policy_arns").AsStringValueSliceOrEmpty(),
		RoleARN:           getStringAttrValue("role_arn", p),
		SessionName:       getStringAttrValue("session_name", p),
		SourceIdentity:    getStringAttrValue("source_identity", p),
		Tags:              p.GetAttribute("tags").AsMapValue(),
		TransitiveTagKeys: p.GetAttribute("transitive_tag_keys").AsStringValueSliceOrEmpty(),
	}
}

func adaptAssumeRoleWithWebIdentity(p *terraform.Block) aws.AssumeRoleWithWebIdentity {
	block := p.GetBlock("assume_role_with_web_identity")
	if block.IsNil() {
		return aws.AssumeRoleWithWebIdentity{
			Metadata:             p.GetMetadata(),
			Duration:             types.StringDefault("", p.GetMetadata()),
			Policy:               types.StringDefault("", p.GetMetadata()),
			RoleARN:              types.StringDefault("", p.GetMetadata()),
			SessionName:          types.StringDefault("", p.GetMetadata()),
			WebIdentityToken:     types.StringDefault("", p.GetMetadata()),
			WebIdentityTokenFile: types.StringDefault("", p.GetMetadata()),
		}
	}

	return aws.AssumeRoleWithWebIdentity{
		Metadata:             block.GetMetadata(),
		Duration:             getStringAttrValue("duration", p),
		Policy:               getStringAttrValue("policy", p),
		PolicyARNs:           p.GetAttribute("policy_arns").AsStringValueSliceOrEmpty(),
		RoleARN:              getStringAttrValue("role_arn", p),
		SessionName:          getStringAttrValue("session_name", p),
		WebIdentityToken:     getStringAttrValue("web_identity_token", p),
		WebIdentityTokenFile: getStringAttrValue("web_identity_token_file", p),
	}
}

func adaptEndpoints(p *terraform.Block) types.MapValue {
	block := p.GetBlock("endpoints")
	if block.IsNil() {
		return types.MapDefault(make(map[string]string), p.GetMetadata())
	}

	values := make(map[string]string)

	for name, attr := range block.Attributes() {
		values[name] = attr.AsStringValueOrDefault("", block).Value()
	}

	return types.Map(values, block.GetMetadata())
}

func adaptDefaultTags(p *terraform.Block) aws.DefaultTags {
	attr, _ := p.GetNestedAttribute("default_tags.tags")
	if attr.IsNil() {
		return aws.DefaultTags{}
	}

	return aws.DefaultTags{
		Metadata: attr.GetMetadata(),
		Tags:     attr.AsMapValue(),
	}
}

func adaptIgnoreTags(p *terraform.Block) aws.IgnoreTags {
	block := p.GetBlock("ignore_tags")
	if block.IsNil() {
		return aws.IgnoreTags{}
	}

	return aws.IgnoreTags{
		Metadata:    block.GetMetadata(),
		Keys:        block.GetAttribute("keys").AsStringValueSliceOrEmpty(),
		KeyPrefixes: block.GetAttribute("key_prefixes").AsStringValueSliceOrEmpty(),
	}
}

func getStringAttrValue(name string, parent *terraform.Block) types.StringValue {
	return parent.GetAttribute(name).AsStringValueOrDefault("", parent)
}
