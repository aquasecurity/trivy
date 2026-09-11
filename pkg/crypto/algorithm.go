package crypto

import (
	"strconv"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DescribeAlgorithm describes the algorithm an OID identifies. The size and the curve
// belong to the key the algorithm is used with and are zero for a signature algorithm.
func DescribeAlgorithm(oid string, size int, curve string) ftypes.CryptoAssetInfo {
	found, known := algorithms[oid]
	if !known {
		// An unrecognized OID is still reported, named by the OID itself. It states no
		// family, no primitive and no parameter, because all three come from the catalog.
		found = algorithm{
			name:      oid,
			primitive: ftypes.CryptoPrimitiveUnknown,
		}
	}

	name := found.name
	var parameters string
	switch {
	case found.parameter == ftypes.CryptoParameterKeySize && size > 0:
		value := strconv.Itoa(size)
		name += "-" + value
		parameters = string(ftypes.CryptoParameterKeySize) + "=" + value
	case found.parameter == ftypes.CryptoParameterCurve && curve != "":
		name += "-" + curve
		parameters = string(ftypes.CryptoParameterCurve) + "=" + curve
	}

	return ftypes.CryptoAssetInfo{
		Kind: ftypes.CryptoKindAlgorithm,
		Identity: ftypes.CryptoIdentity{
			Method:     ftypes.CryptoMethodOID,
			Value:      oid,
			Parameters: parameters,
		},
		Name: name,

		Algorithm: &ftypes.CryptoAlgorithm{
			Family:    found.family,
			Primitive: found.primitive,
		},
	}
}
