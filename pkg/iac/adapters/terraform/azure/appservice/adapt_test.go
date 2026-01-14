package appservice

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptService(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  appservice.AppService
	}{
		{
			name: "configured",
			terraform: `
			resource "azurerm_app_service" "my_example" {
				name                = "example-app-service"
				client_cert_enabled = true
			  
				identity {
				  type = "UserAssigned"
				  identity_ids = "webapp1"
				}
				site_config {
					http2_enabled = true
					min_tls_version = "1.0"

				}
				auth_settings {
					enabled = true
				  }
			}
`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					Resource:         iacTypes.StringTest("azurerm_app_service"),
					EnableClientCert: iacTypes.BoolTest(true),
					Identity: appservice.Identity{
						Type: iacTypes.StringTest("UserAssigned"),
					},
					Authentication: appservice.Authentication{
						Enabled: iacTypes.BoolTest(true),
					},
					Site: appservice.Site{
						EnableHTTP2:       iacTypes.BoolTest(true),
						MinimumTLSVersion: iacTypes.StringTest("1.0"),
					},
				}},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_app_service" "my_example" {
			}
`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					Resource: iacTypes.StringTest("azurerm_app_service"),
					Site: appservice.Site{
						MinimumTLSVersion: iacTypes.StringTest("1.2"),
					},
				}},
			},
		},
		{
			name: "empty azurerm_windows_web_app",
			terraform: `resource "azurerm_windows_web_app" "example" {
  name                = "example"
}`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					Resource: iacTypes.StringTest("azurerm_windows_web_app"),
					Site: appservice.Site{
						MinimumTLSVersion: iacTypes.StringTest("1.2"),
						FTPSState:         iacTypes.StringTest("Disabled"),
					},
				}},
			},
		},
		{
			name: "complete azurerm_windows_web_app",
			terraform: `resource "azurerm_windows_web_app" "example" {
  https_only                 = true
  client_certificate_enabled = true

  identity {
    type = "SystemAssigned"
  }

  auth_settings {
    enabled = true
  }

  site_config {
    http2_enabled       = true
    minimum_tls_version = "1.3"
    ftps_state          = "FtpsOnly"

    application_stack {
      php_version = "7.4"
    }
  }
}
`,
			expected: appservice.AppService{
				Services: []appservice.Service{{
					Resource:         iacTypes.StringTest("azurerm_windows_web_app"),
					HTTPSOnly:        iacTypes.BoolTest(true),
					EnableClientCert: iacTypes.BoolTest(true),
					Identity: appservice.Identity{
						Type: iacTypes.StringTest("SystemAssigned"),
					},
					Authentication: appservice.Authentication{
						Enabled: iacTypes.BoolTest(true),
					},
					Site: appservice.Site{
						EnableHTTP2:       iacTypes.BoolTest(true),
						MinimumTLSVersion: iacTypes.StringTest("1.3"),
						FTPSState:         iacTypes.StringTest("FtpsOnly"),
						PHPVersion:        iacTypes.StringTest("7.4"),
					},
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptFunctionApp(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  appservice.FunctionApp
	}{
		{
			name: "configured",
			terraform: `
			resource "azurerm_function_app" "my_example" {
				name                       = "test-azure-functions"
				https_only                 = true
			}
`,
			expected: appservice.FunctionApp{
				HTTPSOnly: iacTypes.BoolTest(true),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_function_app" "my_example" {		
			}
`,
			expected: appservice.FunctionApp{},
		},
		{
			name: "os-specific resource",
			terraform: `
			resource "azurerm_windows_function_app" "my_example" {
				name                       = "test-azure-functions"
				https_only                 = true
			}
`,
			expected: appservice.FunctionApp{
				HTTPSOnly: iacTypes.BoolTest(true),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptFunctionApp(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_app_service" "my_example" {
		name                = "example-app-service"
		client_cert_enabled = true
	  
		identity {
		  type = "UserAssigned"
		  identity_ids = "webapp1"
		}
		site_config {
			http2_enabled = true
			min_tls_version = "1.0"
		}
		auth_settings {
			enabled = true
		  }
	}
	
	resource "azurerm_function_app" "my_example" {
		name                       = "test-azure-functions"
		https_only                 = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Services, 1)
	require.Len(t, adapted.FunctionApps, 1)

	service := adapted.Services[0]
	functionApp := adapted.FunctionApps[0]

	assert.Equal(t, 4, service.EnableClientCert.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, service.EnableClientCert.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, service.Identity.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, service.Identity.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, service.Site.EnableHTTP2.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, service.Site.EnableHTTP2.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, service.Site.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, service.Site.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, service.Authentication.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, service.Authentication.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, functionApp.HTTPSOnly.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, functionApp.HTTPSOnly.GetMetadata().Range().GetEndLine())
}
