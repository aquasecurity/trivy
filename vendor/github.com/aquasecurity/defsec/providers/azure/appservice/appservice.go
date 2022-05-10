package appservice

import "github.com/aquasecurity/defsec/parsers/types"

type AppService struct {
	types.Metadata
	Services     []Service
	FunctionApps []FunctionApp
}

type Service struct {
	types.Metadata
	EnableClientCert types.BoolValue
	Identity         struct {
		Type types.StringValue
	}
	Authentication struct {
		Enabled types.BoolValue
	}
	Site struct {
		EnableHTTP2       types.BoolValue
		MinimumTLSVersion types.StringValue
	}
}

type FunctionApp struct {
	types.Metadata
	HTTPSOnly types.BoolValue
}
