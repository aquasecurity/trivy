package ecr

import (
	"fmt"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/ecr"
	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func getRepositories(ctx parser.FileContext) (repositories []ecr.Repository) {

	repositoryResources := ctx.GetResourceByType("AWS::ECR::Repository")

	for _, r := range repositoryResources {

		repository := ecr.Repository{
			Metadata: r.Metadata(),
			ImageScanning: ecr.ImageScanning{
				ScanOnPush: r.GetBoolProperty("ImageScanningConfiguration.ScanOnPush"),
			},
			ImageTagsImmutable: hasImmutableImageTags(r),
			Encryption: ecr.Encryption{
				Type:     r.GetStringProperty("EncryptionConfiguration.EncryptionType", ecr.EncryptionTypeAES256),
				KMSKeyID: r.GetStringProperty("EncryptionConfiguration.KmsKey"),
			},
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
		Document: iam.Document{
			Parsed:   *parsed,
			Metadata: policyProp.Metadata(),
		},
	}, nil
}

func hasImmutableImageTags(r *parser.Resource) types.BoolValue {
	mutabilityProp := r.GetProperty("ImageTagMutability")
	if mutabilityProp.IsNil() || !mutabilityProp.EqualTo("IMMUTABLE") {
		return types.BoolDefault(false, r.Metadata())
	}
	return types.Bool(true, mutabilityProp.Metadata())
}
