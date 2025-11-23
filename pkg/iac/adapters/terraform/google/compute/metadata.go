package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// TODO: add support for google_compute_project_metadata_item
// https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata_item
func adaptProjectMetadata(modules terraform.Modules) compute.ProjectMetadata {
	metadata := compute.ProjectMetadata{
		Metadata:      iacTypes.NewUnmanagedMetadata(),
		EnableOSLogin: iacTypes.BoolUnresolvable(iacTypes.NewUnmanagedMetadata()),
	}

	for _, metadataBlock := range modules.GetResourcesByType("google_compute_project_metadata") {
		metadata.Metadata = metadataBlock.GetMetadata()
		if attr := metadataBlock.GetAttribute("metadata"); attr.IsNotNil() {
			flags := parseMetadataFlags(attr)
			metadata.EnableOSLogin = flags.EnableOSLogin
		}
	}
	return metadata
}

func parseMetadataFlags(attr *terraform.Attribute) compute.MetadataFlags {
	flags := compute.MetadataFlags{
		EnableOSLogin:       iacTypes.BoolDefault(false, attr.GetMetadata()),
		BlockProjectSSHKeys: iacTypes.BoolDefault(false, attr.GetMetadata()),
		EnableSerialPort:    iacTypes.BoolDefault(false, attr.GetMetadata()),
	}

	if attr.IsNil() {
		return flags
	}

	meta := attr.GetMetadata()
	if val, ok := iacTypes.BoolFromCtyValue(attr.MapValue("enable-oslogin"), meta); ok {
		flags.EnableOSLogin = val
	}
	if val, ok := iacTypes.BoolFromCtyValue(attr.MapValue("block-project-ssh-keys"), meta); ok {
		flags.BlockProjectSSHKeys = val
	}
	if val, ok := iacTypes.BoolFromCtyValue(attr.MapValue("serial-port-enable"), meta); ok {
		flags.EnableSerialPort = val
	}
	return flags
}
