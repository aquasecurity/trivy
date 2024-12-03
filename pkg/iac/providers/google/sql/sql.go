package sql

import (
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SQL struct {
	Instances []DatabaseInstance
}

const (
	DatabaseFamilyMySQL     = "MYSQL"
	DatabaseFamilyPostgres  = "POSTGRES"
	DatabaseFamilySQLServer = "SQLSERVER"
)

const (
	DatabaseVersionMySQL_5_6                 = "MYSQL_5_6"
	DatabaseVersionMySQL_5_7                 = "MYSQL_5_7"
	DatabaseVersionMySQL_8_0                 = "MYSQL_8_0"
	DatabaseVersionPostgres_9_6              = "POSTGRES_9_6"
	DatabaseVersionPostgres_10               = "POSTGRES_10"
	DatabaseVersionPostgres_11               = "POSTGRES_11"
	DatabaseVersionPostgres_12               = "POSTGRES_12"
	DatabaseVersionPostgres_13               = "POSTGRES_13"
	DatabaseVersionSQLServer_2017_STANDARD   = "SQLSERVER_2017_STANDARD"
	DatabaseVersionSQLServer_2017_ENTERPRISE = "SQLSERVER_2017_ENTERPRISE"
	DatabaseVersionSQLServer_2017_EXPRESS    = "SQLSERVER_2017_EXPRESS"
	DatabaseVersionSQLServer_2017_WEB        = "SQLSERVER_2017_WEB"
)

type DatabaseInstance struct {
	Metadata        iacTypes.Metadata
	DatabaseVersion iacTypes.StringValue
	Settings        Settings
	IsReplica       iacTypes.BoolValue
}

type Settings struct {
	Metadata        iacTypes.Metadata
	Flags           Flags
	Backups         Backups
	IPConfiguration IPConfiguration
}
type Flags struct {
	Metadata                        iacTypes.Metadata
	LogTempFileSize                 iacTypes.IntValue
	LocalInFile                     iacTypes.BoolValue
	ContainedDatabaseAuthentication iacTypes.BoolValue
	CrossDBOwnershipChaining        iacTypes.BoolValue
	LogCheckpoints                  iacTypes.BoolValue
	LogConnections                  iacTypes.BoolValue
	LogDisconnections               iacTypes.BoolValue
	LogLockWaits                    iacTypes.BoolValue
	LogMinMessages                  iacTypes.StringValue // FATAL, PANIC, LOG, ERROR, WARN
	LogMinDurationStatement         iacTypes.IntValue
}

type Backups struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type IPConfiguration struct {
	Metadata           iacTypes.Metadata
	RequireTLS         iacTypes.BoolValue
	SSLMode            iacTypes.StringValue
	EnableIPv4         iacTypes.BoolValue
	AuthorizedNetworks []struct {
		Name iacTypes.StringValue
		CIDR iacTypes.StringValue
	}
}

func (i *DatabaseInstance) DatabaseFamily() string {
	return strings.Split(i.DatabaseVersion.Value(), "_")[0]
}
