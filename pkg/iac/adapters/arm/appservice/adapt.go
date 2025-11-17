package appservice

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) appservice.AppService {
	return appservice.AppService{
		Services:     adaptServices(deployment),
		FunctionApps: adaptFunctionApps(deployment),
	}
}

func adaptFunctionApps(deployment azure.Deployment) []appservice.FunctionApp {
	var functionApps []appservice.FunctionApp

	for _, resource := range deployment.GetResourcesByType("Microsoft.Web/sites") {
		functionApps = append(functionApps, adaptFunctionApp(resource))
	}
	if functionApps == nil {
		return []appservice.FunctionApp{}
	}
	return functionApps
}

func adaptServices(deployment azure.Deployment) []appservice.Service {
	var services []appservice.Service
	for _, resource := range deployment.GetResourcesByType("Microsoft.Web/sites") {
		services = append(services, adaptService(resource))
	}
	if services == nil {
		return []appservice.Service{}
	}
	return services
}

func adaptFunctionApp(resource azure.Resource) appservice.FunctionApp {
	return appservice.FunctionApp{
		Metadata:  resource.Metadata,
		HTTPSOnly: resource.Properties.GetMapValue("httpsOnly").AsBoolValue(false, resource.Properties.GetMetadata()),
	}
}

func adaptService(resource azure.Resource) appservice.Service {
	httpsOnly := resource.Properties.GetMapValue("httpsOnly").AsBoolValue(false, resource.Properties.GetMetadata())

	siteConfig := resource.Properties.GetMapValue("siteConfig")
	enableHTTP2Val := iacTypes.Bool(false, resource.Properties.GetMetadata())
	minTLSVersionVal := iacTypes.String("1.2", resource.Properties.GetMetadata())
	phpVersionVal := iacTypes.String("", resource.Properties.GetMetadata())
	pythonVersionVal := iacTypes.String("", resource.Properties.GetMetadata())
	ftpsStateVal := iacTypes.String("", resource.Properties.GetMetadata())

	if !siteConfig.IsNull() {
		enableHTTP2Val = siteConfig.GetMapValue("http20Enabled").AsBoolValue(false, siteConfig.GetMetadata())
		// Prefer siteConfig.minTlsVersion if it exists (official location)
		if siteConfigMinTLS := siteConfig.GetMapValue("minTlsVersion"); !siteConfigMinTLS.IsNull() {
			minTLSVersionVal = siteConfigMinTLS.AsStringValue("", siteConfig.GetMetadata())
		}
		phpVersionVal = siteConfig.GetMapValue("phpVersion").AsStringValue("", siteConfig.GetMetadata())
		pythonVersionVal = siteConfig.GetMapValue("pythonVersion").AsStringValue("", siteConfig.GetMetadata())
		ftpsStateVal = siteConfig.GetMapValue("ftpsState").AsStringValue("", siteConfig.GetMetadata())
	}

	return appservice.Service{
		Metadata:         resource.Metadata,
		EnableClientCert: resource.Properties.GetMapValue("clientCertEnabled").AsBoolValue(false, resource.Properties.GetMetadata()),
		HTTPSOnly:        httpsOnly,
		Identity: struct{ Type iacTypes.StringValue }{
			Type: resource.Properties.GetMapValue("identity").GetMapValue("type").AsStringValue("", resource.Properties.GetMetadata()),
		},
		Authentication: struct{ Enabled iacTypes.BoolValue }{
			Enabled: resource.Properties.GetMapValue("siteAuthSettings").GetMapValue("enabled").AsBoolValue(false, resource.Properties.GetMetadata()),
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
