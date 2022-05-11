package sql

import (
	"strconv"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
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
		Settings: sql.Settings{
			Metadata: resource.GetMetadata(),
			Flags: sql.Flags{
				Metadata:                        resource.GetMetadata(),
				LogTempFileSize:                 types.IntDefault(-1, resource.GetMetadata()),
				LocalInFile:                     types.BoolDefault(false, resource.GetMetadata()),
				ContainedDatabaseAuthentication: types.BoolDefault(true, resource.GetMetadata()),
				CrossDBOwnershipChaining:        types.BoolDefault(true, resource.GetMetadata()),
				LogCheckpoints:                  types.BoolDefault(false, resource.GetMetadata()),
				LogConnections:                  types.BoolDefault(false, resource.GetMetadata()),
				LogDisconnections:               types.BoolDefault(false, resource.GetMetadata()),
				LogLockWaits:                    types.BoolDefault(false, resource.GetMetadata()),
				LogMinMessages:                  types.StringDefault("", resource.GetMetadata()),
				LogMinDurationStatement:         types.IntDefault(-1, resource.GetMetadata()),
			},
			Backups: sql.Backups{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
			IPConfiguration: sql.IPConfiguration{
				Metadata:           resource.GetMetadata(),
				RequireTLS:         types.BoolDefault(false, resource.GetMetadata()),
				EnableIPv4:         types.BoolDefault(true, resource.GetMetadata()),
				AuthorizedNetworks: nil,
			},
		},
	}

	if settingsBlock := resource.GetBlock("settings"); settingsBlock.IsNotNil() {
		if blocks := settingsBlock.GetBlocks("database_flags"); len(blocks) > 0 {
			adaptFlags(blocks, &instance.Settings.Flags)
		}
		if backupBlock := settingsBlock.GetBlock("backup_configuration"); backupBlock.IsNotNil() {
			backupConfigEnabledAttr := backupBlock.GetAttribute("enabled")
			instance.Settings.Backups.Enabled = backupConfigEnabledAttr.AsBoolValueOrDefault(false, backupBlock)
		}
		if settingsBlock.HasChild("ip_configuration") {
			instance.Settings.IPConfiguration = adaptIPConfig(settingsBlock.GetBlock("ip_configuration"))
		}
	}
	return instance
}

//nolint
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
				flags.LogTempFileSize = types.Int(logTempInt, nameAttr.GetMetadata())
			}
		case "log_min_messages":
			flags.LogMinMessages = valueAttr.AsStringValueOrDefault("", resource)
		case "log_min_duration_statement":
			if logMinDS, err := strconv.Atoi(valueAttr.Value().AsString()); err == nil {
				flags.LogMinDurationStatement = types.Int(logMinDS, nameAttr.GetMetadata())
			}
		case "local_infile":
			flags.LocalInFile = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_checkpoints":
			flags.LogCheckpoints = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_connections":
			flags.LogConnections = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_disconnections":
			flags.LogDisconnections = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "log_lock_waits":
			flags.LogLockWaits = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "contained database authentication":
			flags.ContainedDatabaseAuthentication = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		case "cross db ownership chaining":
			flags.CrossDBOwnershipChaining = types.Bool(valueAttr.Equals("on"), valueAttr.GetMetadata())
		}
	}
}

func adaptIPConfig(resource *terraform.Block) sql.IPConfiguration {
	var authorizedNetworks []struct {
		Name types.StringValue
		CIDR types.StringValue
	}

	tlsRequiredAttr := resource.GetAttribute("require_ssl")
	tlsRequiredVal := tlsRequiredAttr.AsBoolValueOrDefault(false, resource)

	ipv4enabledAttr := resource.GetAttribute("ipv4_enabled")
	ipv4enabledVal := ipv4enabledAttr.AsBoolValueOrDefault(true, resource)

	authNetworksBlocks := resource.GetBlocks("authorized_networks")
	for _, authBlock := range authNetworksBlocks {
		nameVal := authBlock.GetAttribute("name").AsStringValueOrDefault("", authBlock)
		cidrVal := authBlock.GetAttribute("value").AsStringValueOrDefault("", authBlock)

		authorizedNetworks = append(authorizedNetworks, struct {
			Name types.StringValue
			CIDR types.StringValue
		}{
			Name: nameVal,
			CIDR: cidrVal,
		})
	}

	return sql.IPConfiguration{
		Metadata:           resource.GetMetadata(),
		RequireTLS:         tlsRequiredVal,
		EnableIPv4:         ipv4enabledVal,
		AuthorizedNetworks: authorizedNetworks,
	}
}
