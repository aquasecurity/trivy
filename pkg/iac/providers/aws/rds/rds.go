package rds

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type RDS struct {
	Instances       []Instance
	Clusters        []Cluster
	Classic         Classic
	Snapshots       []Snapshots
	ParameterGroups []ParameterGroups
}

type Instance struct {
	Metadata                         defsecTypes.Metadata
	BackupRetentionPeriodDays        defsecTypes.IntValue
	ReplicationSourceARN             defsecTypes.StringValue
	PerformanceInsights              PerformanceInsights
	Encryption                       Encryption
	PublicAccess                     defsecTypes.BoolValue
	Engine                           defsecTypes.StringValue
	IAMAuthEnabled                   defsecTypes.BoolValue
	DeletionProtection               defsecTypes.BoolValue
	DBInstanceArn                    defsecTypes.StringValue
	StorageEncrypted                 defsecTypes.BoolValue
	DBInstanceIdentifier             defsecTypes.StringValue
	DBParameterGroups                []DBParameterGroupsList
	TagList                          []TagList
	EnabledCloudwatchLogsExports     []defsecTypes.StringValue
	EngineVersion                    defsecTypes.StringValue
	AutoMinorVersionUpgrade          defsecTypes.BoolValue
	MultiAZ                          defsecTypes.BoolValue
	PubliclyAccessible               defsecTypes.BoolValue
	LatestRestorableTime             defsecTypes.TimeValue
	ReadReplicaDBInstanceIdentifiers []defsecTypes.StringValue
}

type Cluster struct {
	Metadata                  defsecTypes.Metadata
	BackupRetentionPeriodDays defsecTypes.IntValue
	ReplicationSourceARN      defsecTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              defsecTypes.BoolValue
	Engine                    defsecTypes.StringValue
	LatestRestorableTime      defsecTypes.TimeValue
	AvailabilityZones         []defsecTypes.StringValue
	DeletionProtection        defsecTypes.BoolValue
	SkipFinalSnapshot         defsecTypes.BoolValue
}

type Snapshots struct {
	Metadata             defsecTypes.Metadata
	DBSnapshotIdentifier defsecTypes.StringValue
	DBSnapshotArn        defsecTypes.StringValue
	Encrypted            defsecTypes.BoolValue
	KmsKeyId             defsecTypes.StringValue
	SnapshotAttributes   []DBSnapshotAttributes
}

type Parameters struct {
	Metadata       defsecTypes.Metadata
	ParameterName  defsecTypes.StringValue
	ParameterValue defsecTypes.StringValue
}

type ParameterGroups struct {
	Metadata               defsecTypes.Metadata
	DBParameterGroupName   defsecTypes.StringValue
	DBParameterGroupFamily defsecTypes.StringValue
	Parameters             []Parameters
}

type DBSnapshotAttributes struct {
	Metadata        defsecTypes.Metadata
	AttributeValues []defsecTypes.StringValue
}

const (
	EngineAurora             = "aurora"
	EngineAuroraMysql        = "aurora-mysql"
	EngineAuroraPostgresql   = "aurora-postgresql"
	EngineMySQL              = "mysql"
	EnginePostgres           = "postgres"
	EngineCustomOracleEE     = "custom-oracle-ee"
	EngineOracleEE           = "oracle-ee"
	EngineOracleEECDB        = "oracle-ee-cdb"
	EngineOracleSE2          = "oracle-se2"
	EngineOracleSE2CDB       = "oracle-se2-cdb"
	EngineSQLServerEE        = "sqlserver-ee"
	EngineSQLServerSE        = "sqlserver-se"
	EngineSQLServerEX        = "sqlserver-ex"
	EngineSQLServerWEB       = "sqlserver-web"
	EngineMariaDB            = "mariadb"
	EngineCustomSQLServerEE  = "custom-sqlserver-ee"
	EngineCustomSQLServerSE  = "custom-sqlserver-se"
	EngineCustomSQLServerWEB = "custom-sqlserver-web"
)

type Encryption struct {
	Metadata       defsecTypes.Metadata
	EncryptStorage defsecTypes.BoolValue
	KMSKeyID       defsecTypes.StringValue
}

type ClusterInstance struct {
	Instance
	ClusterIdentifier defsecTypes.StringValue
}

type PerformanceInsights struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

type DBParameterGroupsList struct {
	Metadata             defsecTypes.Metadata
	DBParameterGroupName defsecTypes.StringValue
	KMSKeyID             defsecTypes.StringValue
}

type TagList struct {
	Metadata defsecTypes.Metadata
}
