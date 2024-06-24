package azure

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) azure.Azure {
	return azure.Azure{
		AppService:     appservice.Adapt(modules),
		Authorization:  authorization.Adapt(modules),
		Compute:        compute.Adapt(modules),
		Container:      container.Adapt(modules),
		Database:       database.Adapt(modules),
		DataFactory:    datafactory.Adapt(modules),
		DataLake:       datalake.Adapt(modules),
		KeyVault:       keyvault.Adapt(modules),
		Monitor:        monitor.Adapt(modules),
		Network:        network.Adapt(modules),
		SecurityCenter: securitycenter.Adapt(modules),
		Storage:        storage.Adapt(modules),
		Synapse:        synapse.Adapt(modules),
	}
}
