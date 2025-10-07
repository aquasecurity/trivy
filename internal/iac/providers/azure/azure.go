package azure

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/datalake"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure/synapse"
)

type Azure struct {
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
