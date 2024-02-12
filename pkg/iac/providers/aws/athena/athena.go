package athena

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Athena struct {
	Databases  []Database
	Workgroups []Workgroup
}

type Database struct {
	Metadata   defsecTypes.Metadata
	Name       defsecTypes.StringValue
	Encryption EncryptionConfiguration
}

type Workgroup struct {
	Metadata             defsecTypes.Metadata
	Name                 defsecTypes.StringValue
	Encryption           EncryptionConfiguration
	EnforceConfiguration defsecTypes.BoolValue
}

const (
	EncryptionTypeNone   = ""
	EncryptionTypeSSES3  = "SSE_S3"
	EncryptionTypeSSEKMS = "SSE_KMS"
	EncryptionTypeCSEKMS = "CSE_KMS"
)

type EncryptionConfiguration struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
}
