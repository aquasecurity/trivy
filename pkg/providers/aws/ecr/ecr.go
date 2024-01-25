package ecr

import (
	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	Metadata           defsecTypes.MisconfigMetadata
	ImageScanning      ImageScanning
	ImageTagsImmutable defsecTypes.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	Metadata   defsecTypes.MisconfigMetadata
	ScanOnPush defsecTypes.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue
	KMSKeyID defsecTypes.StringValue
}
