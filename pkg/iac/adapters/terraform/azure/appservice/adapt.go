package appservice

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
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
	for _, resource := range modules.GetResourcesByType("azurerm_linux_web_app", "azurerm_windows_web_app") {
		services = append(services, adaptWebApp(resource))
	}
	return services
}

func adaptFunctionApps(modules terraform.Modules) []appservice.FunctionApp {
	var functionApps []appservice.FunctionApp
	for _, resource := range modules.GetResourcesByType(
		"azurerm_function_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
	) {
		functionApps = append(functionApps, adaptFunctionApp(resource))
	}
	return functionApps
}

func adaptService(resource *terraform.Block) appservice.Service {
	service := appservice.Service{
		Metadata:         resource.GetMetadata(),
		Resource:         types.String(resource.TypeLabel(), resource.GetMetadata()),
		EnableClientCert: resource.GetAttribute("client_cert_enabled").AsBoolValueOrDefault(false, resource),
		HTTPSOnly:        resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
		Site: appservice.Site{
			Metadata:          resource.GetMetadata(),
			MinimumTLSVersion: types.StringDefault("1.2", resource.GetMetadata()),
		},
	}

	if identityBlock := resource.GetBlock("identity"); identityBlock.IsNotNil() {
		service.Identity = appservice.Identity{
			Metadata: identityBlock.GetMetadata(),
			Type:     identityBlock.GetAttribute("type").AsStringValueOrDefault("", identityBlock),
		}
	}

	if authBlock := resource.GetBlock("auth_settings"); authBlock.IsNotNil() {
		service.Authentication = appservice.Authentication{
			Metadata: authBlock.GetMetadata(),
			Enabled:  authBlock.GetAttribute("enabled").AsBoolValueOrDefault(false, authBlock),
		}
	}

	if siteBlock := resource.GetBlock("site_config"); siteBlock.IsNotNil() {
		service.Site = appservice.Site{
			Metadata:          siteBlock.GetMetadata(),
			EnableHTTP2:       siteBlock.GetAttribute("http2_enabled").AsBoolValueOrDefault(false, siteBlock),
			MinimumTLSVersion: siteBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("1.2", siteBlock),
			PHPVersion:        siteBlock.GetAttribute("php_version").AsStringValueOrDefault("", siteBlock),
			PythonVersion:     siteBlock.GetAttribute("python_version").AsStringValueOrDefault("", siteBlock),
			FTPSState:         siteBlock.GetAttribute("ftps_state").AsStringValueOrDefault("", siteBlock),
		}
	}

	return service
}

func adaptFunctionApp(resource *terraform.Block) appservice.FunctionApp {
	return appservice.FunctionApp{
		Metadata:  resource.GetMetadata(),
		HTTPSOnly: resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
	}
}

func adaptWebApp(resource *terraform.Block) appservice.Service {
	service := appservice.Service{
		Metadata:         resource.GetMetadata(),
		Resource:         types.String(resource.TypeLabel(), resource.GetMetadata()),
		EnableClientCert: resource.GetAttribute("client_certificate_enabled").AsBoolValueOrDefault(false, resource),
		HTTPSOnly:        resource.GetAttribute("https_only").AsBoolValueOrDefault(false, resource),
		Site: appservice.Site{
			Metadata:          resource.GetMetadata(),
			FTPSState:         types.StringDefault("Disabled", resource.GetMetadata()),
			MinimumTLSVersion: types.StringDefault("1.2", resource.GetMetadata()),
		},
	}

	if identityBlock := resource.GetBlock("identity"); identityBlock.IsNotNil() {
		service.Identity = appservice.Identity{
			Metadata: identityBlock.GetMetadata(),
			Type:     identityBlock.GetAttribute("type").AsStringValueOrDefault("", identityBlock),
		}
	}

	if authBlock := resource.GetBlock("auth_settings"); authBlock.IsNotNil() {
		service.Authentication = appservice.Authentication{
			Metadata: authBlock.GetMetadata(),
			Enabled:  authBlock.GetAttribute("enabled").AsBoolValueOrDefault(false, authBlock),
		}
	}

	if siteBlock := resource.GetBlock("site_config"); siteBlock.IsNotNil() {
		service.Site = appservice.Site{
			Metadata:          siteBlock.GetMetadata(),
			EnableHTTP2:       siteBlock.GetAttribute("http2_enabled").AsBoolValueOrDefault(false, siteBlock),
			MinimumTLSVersion: siteBlock.GetAttribute("minimum_tls_version").AsStringValueOrDefault("1.2", siteBlock),
			FTPSState:         siteBlock.GetAttribute("ftps_state").AsStringValueOrDefault("Disabled", siteBlock),
		}

		if appStack := siteBlock.GetBlock("application_stack"); appStack.IsNotNil() {
			switch resource.TypeLabel() {
			case "azurerm_linux_web_app":
				service.Site.PHPVersion = appStack.GetAttribute("php_version").AsStringValueOrDefault("", appStack)
				service.Site.PythonVersion = appStack.GetAttribute("python_version").AsStringValueOrDefault("", appStack)
			case "azurerm_windows_web_app":
				// azurerm_windows_web_app does not support configuring the python version
				appStack := siteBlock.GetBlock("application_stack")
				service.Site.PHPVersion = appStack.GetAttribute("php_version").AsStringValueOrDefault("", appStack)
			}
		}
	}
	return service
}
