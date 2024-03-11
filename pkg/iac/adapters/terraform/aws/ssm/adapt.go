package ssm

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) ssm.SSM {
	return ssm.SSM{
		Secrets: adaptSecrets(modules),
	}
}

func adaptSecrets(modules terraform.Modules) []ssm.Secret {
	var secrets []ssm.Secret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_secretsmanager_secret") {
			secrets = append(secrets, adaptSecret(resource, module))
		}
	}
	return secrets
}

func adaptSecret(resource *terraform.Block, module *terraform.Module) ssm.Secret {
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("alias/aws/secretsmanager", resource)

	if KMSKeyIDAttr.IsResourceBlockReference("aws_kms_key") {
		kmsBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource)
		if err == nil {
			KMSKeyIDVal = types.String(kmsBlock.FullName(), kmsBlock.GetMetadata())
		}
	}

	return ssm.Secret{
		Metadata: resource.GetMetadata(),
		KMSKeyID: KMSKeyIDVal,
	}
}
