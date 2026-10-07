package crypto

import (
	"strconv"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DescribeAlgorithm describes the algorithm an OID identifies. The size and the curve
// belong to the key the algorithm is used with and are zero for a signature algorithm.
// Only the ones the catalog names for the OID become part of the identity.
func DescribeAlgorithm(oid string, size int, curve string) ftypes.CryptoAssetInfo {
	found := lookupAlgorithm(oid)

	var parameters ftypes.CryptoAlgorithmParameters
	for _, parameter := range found.parameterNames {
		switch parameter {
		case ftypes.CryptoParameterKeySize:
			parameters.KeySize = size
		case ftypes.CryptoParameterCurve:
			parameters.Curve = curve
		}
	}
	// The name carries the values in the order of the canonical encoding of the parameters.
	name := found.name
	if parameters.KeySize > 0 {
		name += "-" + strconv.Itoa(parameters.KeySize)
	}
	if parameters.Curve != "" {
		name += "-" + parameters.Curve
	}

	return ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      oid,
			Parameters: parameters.String(),
		},
		Name: name,

		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    found.family,
			Primitive: found.primitive,
		},
	}
}
