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
				Services: []appservice.Service{{
					Resource: types.StringTest("Microsoft.Web/sites"),
				}},
				FunctionApps: []appservice.FunctionApp{{}},
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
        "minTlsVersion": "1.3",
        "siteConfig": {
          "http20Enabled": true,
          "minTlsVersion": "1.2",
          "phpVersion": "8.1",
          "pythonVersion": "3.11",
          "ftpsState": "FtpsOnly"
        }
      }
    }
  ]
}`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					Resource:         types.StringTest("Microsoft.Web/sites"),
					EnableClientCert: types.BoolTest(true),
					HTTPSOnly:        types.BoolTest(true),
					Identity: appservice.Identity{
						Type: types.StringTest("SystemAssigned"),
					},
					Authentication: appservice.Authentication{
						Enabled: types.BoolTest(true),
					},
					Site: appservice.Site{
						EnableHTTP2:       types.BoolTest(true),
						MinimumTLSVersion: types.StringTest("1.2"),
						PHPVersion:        types.StringTest("8.1"),
						PythonVersion:     types.StringTest("3.11"),
						FTPSState:         types.StringTest("FtpsOnly"),
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
