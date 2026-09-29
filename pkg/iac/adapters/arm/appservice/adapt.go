package appservice

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
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
	return functionApps
}

func adaptServices(deployment azure.Deployment) []appservice.Service {
	var services []appservice.Service
	for _, resource := range deployment.GetResourcesByType("Microsoft.Web/sites") {
		services = append(services, adaptService(resource))
	}
	return services
}

func adaptFunctionApp(resource azure.Resource) appservice.FunctionApp {
	return appservice.FunctionApp{
		Metadata: resource.Metadata,
		HTTPSOnly: resource.Properties.GetMapValue("httpsOnly").
			AsBoolValue(false, resource.Properties.GetMetadata()),
	}
}

func adaptService(resource azure.Resource) appservice.Service {
	props := resource.Properties
	identity := props.GetMapValue("identity")
	siteAuthSettings := props.GetMapValue("siteAuthSettings")
	siteConfig := props.GetMapValue("siteConfig")
	return appservice.Service{
		Metadata:         resource.Metadata,
		Resource:         types.String("Microsoft.Web/sites", resource.Metadata),
		EnableClientCert: props.GetMapValue("clientCertEnabled").AsBoolValue(false, props.GetMetadata()),
		HTTPSOnly:        props.GetMapValue("httpsOnly").AsBoolValue(false, props.GetMetadata()),
		Identity: appservice.Identity{
			Metadata: identity.GetMetadata(),
			Type: identity.GetMapValue("type").
				AsStringValue("", props.GetMetadata()),
		},
		Authentication: appservice.Authentication{
			Metadata: siteAuthSettings.GetMetadata(),
			Enabled:  siteAuthSettings.GetMapValue("enabled").AsBoolValue(false, props.GetMetadata()),
		},
		Site: appservice.Site{
			EnableHTTP2:       siteConfig.GetMapValue("http20Enabled").AsBoolValue(false, siteConfig.GetMetadata()),
			MinimumTLSVersion: siteConfig.GetMapValue("minTlsVersion").AsStringValue("", siteConfig.GetMetadata()),
			PHPVersion:        siteConfig.GetMapValue("phpVersion").AsStringValue("", siteConfig.GetMetadata()),
			PythonVersion:     siteConfig.GetMapValue("pythonVersion").AsStringValue("", siteConfig.GetMetadata()),
			FTPSState:         siteConfig.GetMapValue("ftpsState").AsStringValue("", siteConfig.GetMetadata()),
		},
	}
}
