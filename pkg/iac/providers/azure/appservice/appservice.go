package appservice

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	Metadata         iacTypes.Metadata
	EnableClientCert iacTypes.BoolValue
	Identity         struct {
		Type iacTypes.StringValue
	}
	Authentication struct {
		Enabled iacTypes.BoolValue
	}
	Site struct {
		EnableHTTP2       iacTypes.BoolValue
		MinimumTLSVersion iacTypes.StringValue
	}
}

type FunctionApp struct {
	Metadata  iacTypes.Metadata
	HTTPSOnly iacTypes.BoolValue
}
