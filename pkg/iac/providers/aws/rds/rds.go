package rds

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type RDS struct {
	Instances       []Instance
	Clusters        []Cluster
	Classic         Classic
	Snapshots       []Snapshots
	ParameterGroups []ParameterGroups
}

type Instance struct {
	Metadata                         iacTypes.Metadata
	BackupRetentionPeriodDays        iacTypes.IntValue
	ReplicationSourceARN             iacTypes.StringValue
	PerformanceInsights              PerformanceInsights
	Encryption                       Encryption
	PublicAccess                     iacTypes.BoolValue
	Engine                           iacTypes.StringValue
	IAMAuthEnabled                   iacTypes.BoolValue
	DeletionProtection               iacTypes.BoolValue
	DBInstanceArn                    iacTypes.StringValue
	StorageEncrypted                 iacTypes.BoolValue
	DBInstanceIdentifier             iacTypes.StringValue
	DBParameterGroups                []DBParameterGroupsList
	TagList                          []TagList
	EnabledCloudwatchLogsExports     []iacTypes.StringValue
	EngineVersion                    iacTypes.StringValue
	AutoMinorVersionUpgrade          iacTypes.BoolValue
	MultiAZ                          iacTypes.BoolValue
	PubliclyAccessible               iacTypes.BoolValue
	LatestRestorableTime             iacTypes.TimeValue
	ReadReplicaDBInstanceIdentifiers []iacTypes.StringValue
}

type Cluster struct {
	Metadata                  iacTypes.Metadata
	BackupRetentionPeriodDays iacTypes.IntValue
	ReplicationSourceARN      iacTypes.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
	PublicAccess              iacTypes.BoolValue
	Engine                    iacTypes.StringValue
	LatestRestorableTime      iacTypes.TimeValue
	AvailabilityZones         []iacTypes.StringValue
	DeletionProtection        iacTypes.BoolValue
	SkipFinalSnapshot         iacTypes.BoolValue
}

type Snapshots struct {
	Metadata             iacTypes.Metadata
	DBSnapshotIdentifier iacTypes.StringValue
	DBSnapshotArn        iacTypes.StringValue
	Encrypted            iacTypes.BoolValue
	KmsKeyId             iacTypes.StringValue
	SnapshotAttributes   []DBSnapshotAttributes
}

type Parameters struct {
	Metadata       iacTypes.Metadata
	ParameterName  iacTypes.StringValue
	ParameterValue iacTypes.StringValue
}

type ParameterGroups struct {
	Metadata               iacTypes.Metadata
	DBParameterGroupName   iacTypes.StringValue
	DBParameterGroupFamily iacTypes.StringValue
	Parameters             []Parameters
}

type DBSnapshotAttributes struct {
	Metadata        iacTypes.Metadata
	AttributeValues []iacTypes.StringValue
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
	Metadata       iacTypes.Metadata
	EncryptStorage iacTypes.BoolValue
	KMSKeyID       iacTypes.StringValue
}

type ClusterInstance struct {
	Instance
	ClusterIdentifier iacTypes.StringValue
}

type PerformanceInsights struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	KMSKeyID iacTypes.StringValue
}

type DBParameterGroupsList struct {
	Metadata             iacTypes.Metadata
	DBParameterGroupName iacTypes.StringValue
	KMSKeyID             iacTypes.StringValue
}

type TagList struct {
	Metadata iacTypes.Metadata
}
