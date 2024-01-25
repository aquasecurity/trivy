package sql

import (
	"strings"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
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
	Metadata        defsecTypes.MisconfigMetadata
	DatabaseVersion defsecTypes.StringValue
	Settings        Settings
	IsReplica       defsecTypes.BoolValue
}

type Settings struct {
	Metadata        defsecTypes.MisconfigMetadata
	Flags           Flags
	Backups         Backups
	IPConfiguration IPConfiguration
}
type Flags struct {
	Metadata                        defsecTypes.MisconfigMetadata
	LogTempFileSize                 defsecTypes.IntValue
	LocalInFile                     defsecTypes.BoolValue
	ContainedDatabaseAuthentication defsecTypes.BoolValue
	CrossDBOwnershipChaining        defsecTypes.BoolValue
	LogCheckpoints                  defsecTypes.BoolValue
	LogConnections                  defsecTypes.BoolValue
	LogDisconnections               defsecTypes.BoolValue
	LogLockWaits                    defsecTypes.BoolValue
	LogMinMessages                  defsecTypes.StringValue // FATAL, PANIC, LOG, ERROR, WARN
	LogMinDurationStatement         defsecTypes.IntValue
}

type Backups struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type IPConfiguration struct {
	Metadata           defsecTypes.MisconfigMetadata
	RequireTLS         defsecTypes.BoolValue
	EnableIPv4         defsecTypes.BoolValue
	AuthorizedNetworks []struct {
		Name defsecTypes.StringValue
		CIDR defsecTypes.StringValue
	}
}

func (i *DatabaseInstance) DatabaseFamily() string {
	return strings.Split(i.DatabaseVersion.Value(), "_")[0]
}
