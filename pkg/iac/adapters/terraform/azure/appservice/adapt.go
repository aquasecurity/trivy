package appservice

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
	siteBlock := resource.GetBlock("site_config")
	enableHTTP2Val := iacTypes.Bool(false, resource.GetMetadata())
	minTLSVersionVal := iacTypes.String("1.2", resource.GetMetadata())
	phpVersionVal := iacTypes.String("", resource.GetMetadata())
	pythonVersionVal := iacTypes.String("", resource.GetMetadata())
	ftpsStateVal := iacTypes.String("", resource.GetMetadata())

	if !siteBlock.IsNil() {
		enableHTTP2Val = siteBlock.GetAttribute("http2_enabled").AsBoolValueOrDefault(false, siteBlock)
		minTLSVersionVal = siteBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("1.2", siteBlock)
		phpVersionVal = siteBlock.GetAttribute("php_version").AsStringValueOrDefault("", siteBlock)
		pythonVersionVal = siteBlock.GetAttribute("python_version").AsStringValueOrDefault("", siteBlock)
		ftpsStateVal = siteBlock.GetAttribute("ftps_state").AsStringValueOrDefault("", siteBlock)
	}

	identityBlock := resource.GetBlock("identity")
	authBlock := resource.GetBlock("auth_settings")

	return appservice.Service{
		Metadata:         resource.GetMetadata(),
		EnableClientCert: resource.GetAttribute("client_cert_enabled").AsBoolValueOrDefault(false, resource),
		HTTPSOnly:        resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
		Identity: struct{ Type iacTypes.StringValue }{
			Type: identityBlock.GetAttribute("type").AsStringValueOrDefault("", identityBlock),
		},
		Authentication: struct{ Enabled iacTypes.BoolValue }{
			Enabled: authBlock.GetAttribute("enabled").AsBoolValueOrDefault(false, authBlock),
		},
		Site: appservice.Site{
			EnableHTTP2:       enableHTTP2Val,
			MinimumTLSVersion: minTLSVersionVal,
			PHPVersion:        phpVersionVal,
			PythonVersion:     pythonVersionVal,
			FTPSState:         ftpsStateVal,
		},
	}
}

func adaptFunctionApp(resource *terraform.Block) appservice.FunctionApp {
	return appservice.FunctionApp{
		Metadata:  resource.GetMetadata(),
		HTTPSOnly: resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
	}
}
