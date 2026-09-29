package athena

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	Metadata   iacTypes.Metadata
	Name       iacTypes.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	Metadata             iacTypes.Metadata
	Name                 iacTypes.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration iacTypes.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
}
