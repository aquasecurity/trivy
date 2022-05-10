package namespace.exceptions

import data.namespaces

exception[ns] {
	ns := data.namespaces[_]
	startswith(ns, "builtin")
}