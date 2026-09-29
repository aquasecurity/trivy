package oracle

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/oracle"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) oracle.Oracle {
	return oracle.Oracle{
		Compute: adaptCompute(modules),
	}
}

func adaptCompute(modules terraform.Modules) oracle.Compute {
	compute := oracle.Compute{
		AddressReservations: nil,
	}

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("opc_compute_ip_address_reservation") {
			addressPoolAttr := resource.GetAttribute("ip_address_pool")
			addressPoolVal := addressPoolAttr.AsStringValueOrDefault("", resource)
			compute.AddressReservations = append(compute.AddressReservations, oracle.AddressReservation{
				Metadata: resource.GetMetadata(),
				Pool:     addressPoolVal,
			})
		}
	}
	return compute
}
