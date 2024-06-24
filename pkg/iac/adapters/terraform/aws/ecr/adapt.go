package ecr

import (
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecr"
	iamp "github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) ecr.ECR {
	return ecr.ECR{
		Repositories: adaptRepositories(modules),
	}
}

func adaptRepositories(modules terraform.Modules) []ecr.Repository {
	var repositories []ecr.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecr_repository") {
			repositories = append(repositories, adaptRepository(resource, module, modules))
		}
	}
	return repositories
}

func adaptRepository(resource *terraform.Block, module *terraform.Module, modules terraform.Modules) ecr.Repository {
	repo := ecr.Repository{
		Metadata: resource.GetMetadata(),
		ImageScanning: ecr.ImageScanning{
			Metadata:   resource.GetMetadata(),
			ScanOnPush: iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		ImageTagsImmutable: iacTypes.BoolDefault(false, resource.GetMetadata()),
		Policies:           nil,
		Encryption: ecr.Encryption{
			Metadata: resource.GetMetadata(),
			Type:     iacTypes.StringDefault("AES256", resource.GetMetadata()),
			KMSKeyID: iacTypes.StringDefault("", resource.GetMetadata()),
		},
	}

	if imageScanningBlock := resource.GetBlock("image_scanning_configuration"); imageScanningBlock.IsNotNil() {
		repo.ImageScanning.Metadata = imageScanningBlock.GetMetadata()
		scanOnPushAttr := imageScanningBlock.GetAttribute("scan_on_push")
		repo.ImageScanning.ScanOnPush = scanOnPushAttr.AsBoolValueOrDefault(false, imageScanningBlock)
	}

	mutabilityAttr := resource.GetAttribute("image_tag_mutability")
	if mutabilityAttr.Equals("IMMUTABLE") {
		repo.ImageTagsImmutable = iacTypes.Bool(true, mutabilityAttr.GetMetadata())
	} else if mutabilityAttr.Equals("MUTABLE") {
		repo.ImageTagsImmutable = iacTypes.Bool(false, mutabilityAttr.GetMetadata())
	}

	policyBlocks := module.GetReferencingResources(resource, "aws_ecr_repository_policy", "repository")
	for _, policyRes := range policyBlocks {
		if policyAttr := policyRes.GetAttribute("policy"); policyAttr.IsString() {

			dataBlock, err := module.GetBlockByID(policyAttr.Value().AsString())
			if err != nil {

				parsed, err := iamgo.ParseString(policyAttr.Value().AsString())
				if err != nil {
					continue
				}

				policy := iamp.Policy{
					Metadata: policyRes.GetMetadata(),
					Name:     iacTypes.StringDefault("", policyRes.GetMetadata()),
					Document: iamp.Document{
						Parsed:   *parsed,
						Metadata: policyAttr.GetMetadata(),
					},
					Builtin: iacTypes.Bool(false, policyRes.GetMetadata()),
				}

				repo.Policies = append(repo.Policies, policy)
			} else if dataBlock.Type() == "data" && dataBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(modules, dataBlock); err == nil {
					policy := iamp.Policy{
						Metadata: policyRes.GetMetadata(),
						Name:     iacTypes.StringDefault("", policyRes.GetMetadata()),
						Document: iamp.Document{
							Parsed:   doc.Document,
							Metadata: doc.Source.GetMetadata(),
							IsOffset: true,
						},
						Builtin: iacTypes.Bool(false, policyRes.GetMetadata()),
					}
					repo.Policies = append(repo.Policies, policy)
				}
			}
		}
	}

	if encryptBlock := resource.GetBlock("encryption_configuration"); encryptBlock.IsNotNil() {
		repo.Encryption.Metadata = encryptBlock.GetMetadata()
		encryptionTypeAttr := encryptBlock.GetAttribute("encryption_type")
		repo.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("AES256", encryptBlock)

		kmsKeyAttr := encryptBlock.GetAttribute("kms_key")
		repo.Encryption.KMSKeyID = kmsKeyAttr.AsStringValueOrDefault("", encryptBlock)
		if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
			if keyBlock, err := module.GetReferencedBlock(kmsKeyAttr, encryptBlock); err == nil {
				repo.Encryption.KMSKeyID = iacTypes.String(keyBlock.FullName(), keyBlock.GetMetadata())
			}
		}
	}

	return repo
}
