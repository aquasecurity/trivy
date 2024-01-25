package ecr

import (
	"fmt"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/liamg/iamgo"
)

func getRepositories(ctx parser.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourcesByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {

		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				Metadata:   r.Metadata(),
				ScanOnPush: defsecTypes.BoolDefault(false, r.Metadata()),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Policies:           nil,
			Encryption: ecr.Encryption{
				Metadata: r.Metadata(),
				Type:     defsecTypes.StringDefault(ecr.EncryptionTypeAES256, r.Metadata()),
				KMSKeyID: defsecTypes.StringDefault("", r.Metadata()),
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

func getPolicy(r *parser.Resource) (*iam.Policy, error) {
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
		Name:     defsecTypes.StringDefault("", policyProp.Metadata()),
		Document: iam.Document{
			Metadata: policyProp.Metadata(),
			Parsed:   *parsed,
		},
		Builtin: defsecTypes.Bool(false, policyProp.Metadata()),
	}, nil
}

func hasImmutableImageTags(r *parser.Resource) defsecTypes.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() {
		return defsecTypes.BoolDefault(false, r.Metadata())
	}
	if !mutabilityProp.EqualTo("IMMUTABLE") {
		return defsecTypes.Bool(false, mutabilityProp.Metadata())
	}
	return defsecTypes.Bool(true, mutabilityProp.Metadata())
}
