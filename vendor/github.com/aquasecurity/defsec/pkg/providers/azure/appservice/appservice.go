package appservice

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type AppService struct {
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
