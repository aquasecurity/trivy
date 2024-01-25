package appservice

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type AppService struct {
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	Metadata         defsecTypes.MisconfigMetadata
	EnableClientCert defsecTypes.BoolValue
	Identity         struct {
		Type defsecTypes.StringValue
	}
	Authentication struct {
		Enabled defsecTypes.BoolValue
	}
	Site struct {
		EnableHTTP2       defsecTypes.BoolValue
		MinimumTLSVersion defsecTypes.StringValue
	}
}

type FunctionApp struct {
	Metadata  defsecTypes.MisconfigMetadata
	HTTPSOnly defsecTypes.BoolValue
}
