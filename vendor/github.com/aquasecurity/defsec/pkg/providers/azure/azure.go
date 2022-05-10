package azure

import (
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	"github.com/aquasecurity/defsec/pkg/providers/azure/authorization"
	"github.com/aquasecurity/defsec/pkg/providers/azure/compute"
	"github.com/aquasecurity/defsec/pkg/providers/azure/container"
	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/providers/azure/datafactory"
	"github.com/aquasecurity/defsec/pkg/providers/azure/datalake"
	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/defsec/pkg/providers/azure/monitor"
	"github.com/aquasecurity/defsec/pkg/providers/azure/network"
	"github.com/aquasecurity/defsec/pkg/providers/azure/securitycenter"
	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/providers/azure/synapse"
)

type Azure struct {
	types.Metadata
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
