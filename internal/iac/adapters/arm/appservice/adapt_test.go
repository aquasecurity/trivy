package appservice

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected appservice.AppService
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "properties": {}
    }
  ]
}`,
			expected: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{{}},
				Services:     []appservice.Service{{}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "properties": {
        "httpsOnly": true,
        "clientCertEnabled": true,
        "identity": {
          "type": "SystemAssigned"
        },
        "siteAuthSettings": {
          "enabled": true
        },
        "minTlsVersion": "1.3"
      }
    }
  ]
}`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					EnableClientCert: types.BoolTest(true),
					Identity: struct{ Type types.StringValue }{
						Type: types.StringTest("SystemAssigned"),
					},
					Authentication: struct{ Enabled types.BoolValue }{
						Enabled: types.BoolTest(true),
					},
					Site: struct {
						EnableHTTP2       types.BoolValue
						MinimumTLSVersion types.StringValue
					}{
						EnableHTTP2:       types.BoolTest(true),
						MinimumTLSVersion: types.StringTest("1.3"),
					},
				}},
				FunctionApps: []appservice.FunctionApp{{
					HTTPSOnly: types.BoolTest(true),
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
