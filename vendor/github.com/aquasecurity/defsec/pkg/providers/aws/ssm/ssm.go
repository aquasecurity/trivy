package ssm

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	types.Metadata
	KMSKeyID types.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
