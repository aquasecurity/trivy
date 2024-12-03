package sql

import (
	"strconv"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) sql.SQL {
	return sql.SQL{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform.Modules) []sql.DatabaseInstance {
	var instances []sql.DatabaseInstance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_sql_database_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *terraform.Block) sql.DatabaseInstance {

	instance := sql.DatabaseInstance{
		Metadata:        resource.GetMetadata(),
		DatabaseVersion: resource.GetAttribute("database_version").AsStringValueOrDefault("", resource),
		IsReplica:       iacTypes.BoolDefault(false, resource.GetMetadata()),
		Settings: sql.Settings{
			Metadata: resource.GetMetadata(),
			Flags: sql.Flags{
				Metadata:                        resource.GetMetadata(),
				LogTempFileSize:                 iacTypes.IntDefault(-1, resource.GetMetadata()),
				LocalInFile:                     iacTypes.BoolDefault(false, resource.GetMetadata()),
				ContainedDatabaseAuthentication: iacTypes.BoolDefault(true, resource.GetMetadata()),
				CrossDBOwnershipChaining:        iacTypes.BoolDefault(true, resource.GetMetadata()),
				LogCheckpoints:                  iacTypes.BoolDefault(false, resource.GetMetadata()),
				LogConnections:                  iacTypes.BoolDefault(false, resource.GetMetadata()),
				LogDisconnections:               iacTypes.BoolDefault(false, resource.GetMetadata()),
				LogLockWaits:                    iacTypes.BoolDefault(false, resource.GetMetadata()),
				LogMinMessages:                  iacTypes.StringDefault("", resource.GetMetadata()),
				LogMinDurationStatement:         iacTypes.IntDefault(-1, resource.GetMetadata()),
			},
			Backups: sql.Backups{
				Metadata: resource.GetMetadata(),
				Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			},
			IPConfiguration: sql.IPConfiguration{
				Metadata:           resource.GetMetadata(),
				RequireTLS:         iacTypes.BoolDefault(false, resource.GetMetadata()),
				SSLMode:            iacTypes.String("", resource.GetMetadata()),
				EnableIPv4:         iacTypes.BoolDefault(true, resource.GetMetadata()),
				AuthorizedNetworks: nil,
			},
		},
	}

	if attr := resource.GetAttribute("master_instance_name"); attr.IsNotNil() {
		instance.IsReplica = iacTypes.Bool(true, attr.GetMetadata())
	}

	if settingsBlock := resource.GetBlock("settings"); settingsBlock.IsNotNil() {
		instance.Settings.Metadata = settingsBlock.GetMetadata()
		if blocks := settingsBlock.GetBlocks("database_flags"); len(blocks) > 0 {
			adaptFlags(blocks, &instance.Settings.Flags)
		}
		if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNotNil() {
			instance.Settings.Backups.Metadata = backupBlock.GetMetadata()
			backupConfigEnabledAttr := backupBlock.GetAttribute("enabled")
			instance.Settings.Backups.Enabled = backupConfigEnabledAttr.AsBoolValueOrDefault(false, backupBlock)
		}
		if settingsBlock.HasChild("ip_configuration") {
			instance.Settings.IPConfiguration = adaptIPConfig(settingsBlock.GetBlock("ip_configuration"))
		}
	}
	return instance
}

// nolint
func adaptFlags(resources terraform.Blocks, flags *sql.Flags) {
	for _, resource := range resources {

		nameAttr := resource.GetAttribute("name")
		valueAttr := resource.GetAttribute("value")

		if !nameAttr.IsString() || valueAttr.IsNil() {
			continue
		}

		switch nameAttr.Value().AsString() {
		case "log_temp_files":
			if logTempInt, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogTempFileSize = iacTypes.Int(logTempInt, nameAttr.GetMetadata())
			}
		case "log_min_messages":
			flags.LogMinMessages = valueAttr.AsStringValueOrDefault("", resource)
		case "log_min_duration_statement":
			if logMinDS, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogMinDurationStatement = iacTypes.Int(logMinDS, nameAttr.GetMetadata())
			}
		case "local_infile":
			flags.LocalInFile = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_checkpoints":
			flags.LogCheckpoints = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_connections":
			flags.LogConnections = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_disconnections":
			flags.LogDisconnections = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_lock_waits":
			flags.LogLockWaits = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "contained database authentication":
			flags.ContainedDatabaseAuthentication = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "cross db ownership chaining":
			flags.CrossDBOwnershipChaining = iacTypes.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		}
	}
}

func adaptIPConfig(resource *terraform.Block) sql.IPConfiguration {
	var authorizedNetworks []struct {
		Name iacTypes.StringValue
		CIDR iacTypes.StringValue
	}

	authNetworksBlocks := resource.GetBlocks("authorized_networks")
	for _, authBlock := range authNetworksBlocks {
		nameVal := authBlock.GetAttribute("name").AsStringValueOrDefault("", authBlock)
		cidrVal := authBlock.GetAttribute("value").AsStringValueOrDefault("", authBlock)

		authorizedNetworks = append(authorizedNetworks, struct {
			Name iacTypes.StringValue
			CIDR iacTypes.StringValue
		}{
			Name: nameVal,
			CIDR: cidrVal,
		})
	}

	return sql.IPConfiguration{
		Metadata:           resource.GetMetadata(),
		RequireTLS:         resource.GetAttribute("require_ssl").AsBoolValueOrDefault(false, resource),
		SSLMode:            resource.GetAttribute("ssl_mode").AsStringValueOrDefault("", resource),
		EnableIPv4:         resource.GetAttribute("ipv4_enabled").AsBoolValueOrDefault(true, resource),
		AuthorizedNetworks: authorizedNetworks,
	}
}
