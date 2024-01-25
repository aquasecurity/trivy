package ssm

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	Metadata defsecTypes.MisconfigMetadata
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
