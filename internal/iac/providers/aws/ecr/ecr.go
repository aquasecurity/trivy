package ecr

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ECR struct {
	Repositories []Repository
}

type Repository struct {
	Metadata           iacTypes.Metadata
	ImageScanning      ImageScanning
	ImageTagsImmutable iacTypes.BoolValue
	Policies           []iam.Policy
	Encryption         Encryption
}

type ImageScanning struct {
	Metadata   iacTypes.Metadata
	ScanOnPush iacTypes.BoolValue
}

const (
	EncryptionTypeKMS    = "KMS"
	EncryptionTypeAES256 = "AES256"
)

type Encryption struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
	KMSKeyID iacTypes.StringValue
}
