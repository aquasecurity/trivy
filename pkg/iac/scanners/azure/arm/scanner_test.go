package arm

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func TestScanFlexibleDatabaseServers(t *testing.T) {
	tests := []struct {
		name             string
		template         string
		wantFailedIDs    []string
		wantNotFailedIDs []string
	}{
		{
			name: "postgresql flexible server with public firewall rule triggers AZU-0029",
			template: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "example",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
      "name": "example/allow-all",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    }
  ]
}`,
			wantFailedIDs:    []string{"AZU-0029", "AZU-0022", "AZU-0019", "AZU-0021", "AZU-0024"},
			wantNotFailedIDs: []string{"AZU-0020", "AZU-0026"},
		},
		{
			name: "mysql flexible server with insecure configs and public firewall rule triggers checks",
			template: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "name": "example",
      "properties": {},
      "resources": [
        {
          "type": "firewallRules",
          "name": "allow-all",
          "properties": {
            "startIpAddress": "0.0.0.0",
            "endIpAddress": "255.255.255.255"
          }
        },
        {
          "type": "configurations",
          "name": "require_secure_transport",
          "properties": {
            "value": "OFF"
          }
        },
        {
          "type": "configurations",
          "name": "tls_version",
          "properties": {
            "value": "TLSv1.1,TLSv1.2"
          }
        }
      ]
    }
  ]
}`,
			wantFailedIDs: []string{"AZU-0029", "AZU-0020", "AZU-0022", "AZU-0026"},
		},
		{
			name: "hardened postgresql flexible server passes database checks",
			template: `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "example",
      "properties": {
        "network": {
          "publicNetworkAccess": "Disabled"
        }
      },
      "resources": [
        {
          "type": "firewallRules",
          "name": "office",
          "properties": {
            "startIpAddress": "40.112.8.12",
            "endIpAddress": "40.112.8.12"
          }
        },
        {
          "type": "configurations",
          "name": "log_checkpoints",
          "properties": {
            "value": "ON"
          }
        },
        {
          "type": "configurations",
          "name": "log_connections",
          "properties": {
            "value": "ON"
          }
        },
        {
          "type": "configurations",
          "name": "connection_throttle.enable",
          "properties": {
            "value": "ON"
          }
        }
      ]
    }
  ]
}`,
			wantNotFailedIDs: []string{"AZU-0019", "AZU-0020", "AZU-0021", "AZU-0022", "AZU-0024", "AZU-0026", "AZU-0029"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"template.json": {Data: []byte(tt.template)},
			}

			scanner := New(
				rego.WithEmbeddedLibraries(true),
				rego.WithEmbeddedPolicies(true),
			)

			results, err := scanner.ScanFS(t.Context(), fsys, ".")
			require.NoError(t, err)

			var failedIDs []string
			for _, res := range results.GetFailed() {
				failedIDs = append(failedIDs, res.Rule().ID)
			}

			for _, id := range tt.wantFailedIDs {
				assert.Contains(t, failedIDs, id)
			}
			for _, id := range tt.wantNotFailedIDs {
				assert.NotContains(t, failedIDs, id)
			}
		})
	}
}
