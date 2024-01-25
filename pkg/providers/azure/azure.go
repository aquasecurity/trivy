package azure

import (
	"github.com/aquasecurity/trivy/pkg/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/providers/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/providers/azure/synapse"
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
