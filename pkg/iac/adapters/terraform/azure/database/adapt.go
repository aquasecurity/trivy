package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) database.Database {
	return database.Database{
		MSSQLServers:      adaptMSSQLServers(modules),
		MariaDBServers:    adaptMariaDBServers(modules),
		MySQLServers:      adaptMySQLServers(modules),
		PostgreSQLServers: adaptPostgreSQLServers(modules),
	}
}
