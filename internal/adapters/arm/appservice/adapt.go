package appservice

import (
	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/azure"
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
		Metadata:  resource.Metadata,
		HTTPSOnly: resource.Properties.GetMapValue("httpsOnly").AsBoolValue(false, resource.Properties.GetMetadata()),
	}
}

func adaptService(resource azure.Resource) appservice.Service {
	return appservice.Service{
		Metadata:         resource.Metadata,
		EnableClientCert: resource.Properties.GetMapValue("clientCertEnabled").AsBoolValue(false, resource.Properties.GetMetadata()),
		Identity: struct{ Type defsecTypes.StringValue }{
			Type: resource.Properties.GetMapValue("identity").GetMapValue("type").AsStringValue("", resource.Properties.GetMetadata()),
		},
		Authentication: struct{ Enabled defsecTypes.BoolValue }{
			Enabled: resource.Properties.GetMapValue("siteAuthSettings").GetMapValue("enabled").AsBoolValue(false, resource.Properties.GetMetadata()),
		},
		Site: struct {
			EnableHTTP2       defsecTypes.BoolValue
			MinimumTLSVersion defsecTypes.StringValue
		}{
			EnableHTTP2:       resource.Properties.GetMapValue("httpsOnly").AsBoolValue(false, resource.Properties.GetMetadata()),
			MinimumTLSVersion: resource.Properties.GetMapValue("minTlsVersion").AsStringValue("", resource.Properties.GetMetadata()),
		},
	}
}
