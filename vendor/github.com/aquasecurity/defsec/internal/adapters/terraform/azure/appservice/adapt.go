package appservice

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) appservice.AppService {
	return appservice.AppService{
		Services:     adaptServices(modules),
		FunctionApps: adaptFunctionApps(modules),
	}
}

func adaptServices(modules terraform.Modules) []appservice.Service {
	var services []appservice.Service

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_app_service") {
			services = append(services, adaptService(resource))
		}
	}
	return services
}

func adaptFunctionApps(modules terraform.Modules) []appservice.FunctionApp {
	var functionApps []appservice.FunctionApp

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_function_app") {
			functionApps = append(functionApps, adaptFunctionApp(resource))
		}
	}
	return functionApps
}

func adaptService(resource *terraform.Block) appservice.Service {
	enableClientCertAttr := resource.GetAttribute("client_cert_enabled")
	enableClientCertVal := enableClientCertAttr.AsBoolValueOrDefault(false, resource)

	identityBlock := resource.GetBlock("identity")
	typeVal := types.String("", resource.GetMetadata())
	if identityBlock.IsNotNil() {
		typeAttr := identityBlock.GetAttribute("type")
		typeVal = typeAttr.AsStringValueOrDefault("", identityBlock)
	}

	authBlock := resource.GetBlock("auth_settings")
	enabledVal := types.Bool(false, resource.GetMetadata())
	if authBlock.IsNotNil() {
		enabledAttr := authBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, authBlock)
	}

	siteBlock := resource.GetBlock("site_config")
	enableHTTP2Val := types.Bool(false, resource.GetMetadata())
	minTLSVersionVal := types.String("1.2", resource.GetMetadata())
	if siteBlock.IsNotNil() {
		enableHTTP2Attr := siteBlock.GetAttribute("http2_enabled")
		enableHTTP2Val = enableHTTP2Attr.AsBoolValueOrDefault(false, siteBlock)

		minTLSVersionAttr := siteBlock.GetAttribute("min_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("1.2", siteBlock)
	}

	return appservice.Service{
		Metadata:         resource.GetMetadata(),
		EnableClientCert: enableClientCertVal,
		Identity: struct{ Type types.StringValue }{
			Type: typeVal,
		},
		Authentication: struct{ Enabled types.BoolValue }{
			Enabled: enabledVal,
		},
		Site: struct {
			EnableHTTP2       types.BoolValue
			MinimumTLSVersion types.StringValue
		}{
			EnableHTTP2:       enableHTTP2Val,
			MinimumTLSVersion: minTLSVersionVal,
		},
	}
}

func adaptFunctionApp(resource *terraform.Block) appservice.FunctionApp {
	HTTPSOnlyAttr := resource.GetAttribute("https_only")
	HTTPSOnlyVal := HTTPSOnlyAttr.AsBoolValueOrDefault(false, resource)

	return appservice.FunctionApp{
		Metadata:  resource.GetMetadata(),
		HTTPSOnly: HTTPSOnlyVal,
	}
}
