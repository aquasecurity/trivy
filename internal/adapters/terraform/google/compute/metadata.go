package compute

import (
	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/zclconf/go-cty/cty"
)

func adaptProjectMetadata(modules terraform.Modules) compute.ProjectMetadata {
	metadata := compute.ProjectMetadata{
		Metadata: defsecTypes.NewUnmanagedMetadata(),
		EnableOSLogin: defsecTypes.BoolUnresolvable(
			defsecTypes.NewUnmanagedMetadata(),
		),
	}
	for _, metadataBlock := range modules.GetResourcesByType("google_compute_project_metadata") {
		metadata.Metadata = metadataBlock.GetMetadata()
		if metadataAttr := metadataBlock.GetAttribute("metadata"); metadataAttr.IsNotNil() {
			if val := metadataAttr.MapValue("enable-oslogin"); val.Type() == cty.Bool {
				metadata.EnableOSLogin = defsecTypes.BoolExplicit(val.True(), metadataAttr.GetMetadata())
			}
		}
	}
	return metadata
}
