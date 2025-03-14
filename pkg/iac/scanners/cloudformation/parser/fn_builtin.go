package parser

import (
	"errors"
	"net"

	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func GetAzs(property *Property) (*Property, bool) {
	return property.deriveResolved(cftypes.List, []*Property{
		property.deriveResolved(cftypes.String, "us-east-1a"),
		property.deriveResolved(cftypes.String, "us-east-1a"),
		property.deriveResolved(cftypes.String, "us-east-1a"),
	}), true
}

func GetCidr(property *Property) (*Property, bool) {
	if !property.isFunction() {
		return property, true
	}

	refValue := property.AsMap()["Fn::Cidr"]
	if refValue.IsNotList() || len(refValue.AsList()) != 3 {
		return abortIntrinsic(property, "Fn::Cidr expects a list of 3 attributes")
	}

	listParts := refValue.AsList()
	ipaddressProp := listParts[0]
	ipAddress := "10.0.0.0/2"
	if ipaddressProp.IsString() {
		ipAddress = ipaddressProp.AsString()
	}
	count := listParts[1].AsInt()
	bit := listParts[2].AsInt()

	ranges, err := calculateCidrs(ipAddress, count, bit, property)
	if err != nil {
		return abortIntrinsic(property, "Could not calculate the required ranges")
	}
	return property.deriveResolved(cftypes.List, ranges), true
}

func calculateCidrs(ipaddress string, count, bit int, original *Property) ([]*Property, error) {

	var cidrProperties []*Property

	_, network, err := net.ParseCIDR(ipaddress)
	if err != nil {
		return nil, err
	}

	for i := 0; i < count; i++ {
		next, err := cidr.Subnet(network, bit, i)
		if err != nil {
			return nil, errors.New("failed to create cidr blocks")
		}

		cidrProperties = append(cidrProperties, original.deriveResolved(cftypes.String, next.String()))
	}

	return cidrProperties, nil
}
