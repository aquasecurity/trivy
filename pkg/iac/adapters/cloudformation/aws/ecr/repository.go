package ecr

import (
	"fmt"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func getRepositories(ctx parser2.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourcesByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {

		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				Metadata:   r.Metadata(),
				ScanOnPush: iacTypes.BoolDefault(false, r.Metadata()),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Policies:           nil,
			Encryption: ecr.Encryption{
				Metadata: r.Metadata(),
				Type:     iacTypes.StringDefault(ecr.EncryptionTypeAES256, r.Metadata()),
				KMSKeyID: iacTypes.StringDefault("", r.Metadata()),
			},
		}

		if imageScanningProp := r.GetProperty("ImageScanningConfiguration"); imageScanningProp.IsNotNil() {
			repository.ImageScanning = ecr.ImageScanning{
				Metadata:   imageScanningProp.Metadata(),
				ScanOnPush: imageScanningProp.GetBoolProperty("ScanOnPush", false),
			}
		}

		if encProp := r.GetProperty("EncryptionConfiguration"); encProp.IsNotNil() {
			repository.Encryption = ecr.Encryption{
				Metadata: encProp.Metadata(),
				Type:     encProp.GetStringProperty("EncryptionType", ecr.EncryptionTypeAES256),
				KMSKeyID: encProp.GetStringProperty("KmsKey", ""),
			}
		}

		if policy, err := getPolicy(r); err == nil {
			repository.Policies = append(repository.Policies, *policy)
		}

		repositories = append(repositories, repository)
	}

	return repositories
}

func getPolicy(r *parser2.Resource) (*iam.Policy, error) {
	policyProp := r.GetProperty("RepositoryPolicyText")
	if policyProp.IsNil() {
		return nil, fmt.Errorf("missing policy")
	}

	parsed, err := iamgo.Parse(policyProp.GetJsonBytes())
	if err != nil {
		return nil, err
	}

	return &iam.Policy{
		Metadata: policyProp.Metadata(),
		Name:     iacTypes.StringDefault("", policyProp.Metadata()),
		Document: iam.Document{
			Metadata: policyProp.Metadata(),
			Parsed:   *parsed,
		},
		Builtin: iacTypes.Bool(false, policyProp.Metadata()),
	}, nil
}

func hasImmutableImageTags(r *parser2.Resource) iacTypes.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() {
		return iacTypes.BoolDefault(false, r.Metadata())
	}
	if !mutabilityProp.EqualTo("IMMUTABLE") {
		return iacTypes.Bool(false, mutabilityProp.Metadata())
	}
	return iacTypes.Bool(true, mutabilityProp.Metadata())
}
