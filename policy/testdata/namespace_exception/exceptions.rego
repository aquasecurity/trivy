package namespace.exceptions

import data.namespaces

exception[ns] {
	ns := data.namespaces[_]
	ns == "testdata.kubernetes.xyz_100"
}
