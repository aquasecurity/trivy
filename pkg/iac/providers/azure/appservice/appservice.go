package appservice

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Identity struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
}

type Authentication struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type Service struct {
	Metadata         iacTypes.Metadata
	Resource         iacTypes.StringValue
	EnableClientCert iacTypes.BoolValue
	HTTPSOnly        iacTypes.BoolValue
	Identity         Identity
	Authentication   Authentication
	Site             Site
}

type Site struct {
	Metadata          iacTypes.Metadata
	EnableHTTP2       iacTypes.BoolValue
	MinimumTLSVersion iacTypes.StringValue
	PHPVersion        iacTypes.StringValue
	PythonVersion     iacTypes.StringValue
	FTPSState         iacTypes.StringValue
}

type FunctionApp struct {
	Metadata  iacTypes.Metadata
	HTTPSOnly iacTypes.BoolValue
}
