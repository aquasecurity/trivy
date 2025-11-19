package appservice

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) appservice.AppService {
	return appservice.AppService{
		Services:     adaptServices(modules),
		FunctionApps: adaptFunctionApps(modules),
	}
}

func adaptServices(modules terraform.Modules) []appservice.Service {
	var services []appservice.Service
	for _, resource := range modules.GetResourcesByType("azurerm_app_service") {
		services = append(services, adaptService(resource))
	}
	return services
}

func adaptFunctionApps(modules terraform.Modules) []appservice.FunctionApp {
	var functionApps []appservice.FunctionApp
	for _, resource := range modules.GetResourcesByType("azurerm_function_app") {
		functionApps = append(functionApps, adaptFunctionApp(resource))
	}
	return functionApps
}

func adaptService(resource *terraform.Block) appservice.Service {
	siteBlock := resource.GetBlock("site_config")
	identityBlock := resource.GetBlock("identity")
	authBlock := resource.GetBlock("auth_settings")
	return appservice.Service{
		Metadata:         resource.GetMetadata(),
		EnableClientCert: resource.GetAttribute("client_cert_enabled").AsBoolValueOrDefault(false, resource),
		HTTPSOnly:        resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
		Identity: appservice.Identity{
			Metadata: lo.TernaryF(identityBlock.IsNil(), resource.GetMetadata, identityBlock.GetMetadata),
			Type:     identityBlock.GetAttribute("type").AsStringValueOrDefault("", identityBlock),
		},
		Authentication: appservice.Authentication{
			Metadata: lo.TernaryF(identityBlock.IsNil(), resource.GetMetadata, authBlock.GetMetadata),
			Enabled:  authBlock.GetAttribute("enabled").AsBoolValueOrDefault(false, authBlock),
		},
		Site: appservice.Site{
			Metadata:          lo.TernaryF(identityBlock.IsNil(), resource.GetMetadata, siteBlock.GetMetadata),
			EnableHTTP2:       siteBlock.GetAttribute("http2_enabled").AsBoolValueOrDefault(false, siteBlock),
			MinimumTLSVersion: siteBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("1.2", siteBlock),
			PHPVersion:        siteBlock.GetAttribute("php_version").AsStringValueOrDefault("", siteBlock),
			PythonVersion:     siteBlock.GetAttribute("python_version").AsStringValueOrDefault("", siteBlock),
			FTPSState:         siteBlock.GetAttribute("ftps_state").AsStringValueOrDefault("", siteBlock),
		},
	}
}

func adaptFunctionApp(resource *terraform.Block) appservice.FunctionApp {
	return appservice.FunctionApp{
		Metadata:  resource.GetMetadata(),
		HTTPSOnly: resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
	}
}
