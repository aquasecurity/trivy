package github

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Action struct {
	Metadata           defsecTypes.MisconfigMetadata
	EnvironmentSecrets []EnvironmentSecret
}

type EnvironmentSecret struct {
	Metadata       defsecTypes.MisconfigMetadata
	Repository     defsecTypes.StringValue
	Environment    defsecTypes.StringValue
	SecretName     defsecTypes.StringValue
	PlainTextValue defsecTypes.StringValue
	EncryptedValue defsecTypes.StringValue
}
