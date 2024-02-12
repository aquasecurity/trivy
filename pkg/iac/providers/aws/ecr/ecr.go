package ecr

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	Metadata           defsecTypes.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable defsecTypes.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	Metadata   defsecTypes.Metadata
	ScanOnPush defsecTypes.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}
