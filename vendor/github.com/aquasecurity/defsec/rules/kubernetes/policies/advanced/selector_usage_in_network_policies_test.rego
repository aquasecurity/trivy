package appshield.kubernetes.KSV038

test_networkpolicy_with_spec_pod_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {
			"podSelector": {"matchLabels": {"app": "nginx"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"access": "true"}}}]}],
		},
	}

	count(r) == 0
}

test_networkpolicy_without_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {"ingress": [{"from": [{}]}]},
	}

	r[_].msg == "Network policy should uses podSelector and/or the namespaceSelector to restrict ingress and egress traffic within the Pod network"
}

test_networkpolicy_with_spec_namespace_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {
			"namespaceSelector": {"matchLabels": {"app": "nginx"}},
			"ingress": [{"from": [{"podSelector": {"matchLabels": {"access": "true"}}}]}],
		},
	}

	count(r) == 0
}

test_networkpolicy_with_ingress_pod_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {"ingress": [{"from": [{"podSelector": {"matchLabels": {"access": "true"}}}]}]},
	}

	count(r) == 0
}

test_networkpolicy_with_ingress_namespace_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"access": "true"}}}]}]},
	}

	count(r) == 0
}

test_networkpolicy_with_egress_namespace_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {"egress": [{"to": [{"namespaceSelector": {"matchLabels": {"access": "true"}}}]}]},
	}

	count(r) == 0
}

test_networkpolicy_with_egress_pod_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "access-nginx"},
		"spec": {"egress": [{"to": [{"podSelector": {"matchLabels": {"access": "true"}}}]}]},
	}

	count(r) == 0
}

test_networkpolicy_with_deny_all_egress_pod_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "deny-all-egress"},
		"spec": {
			"podSelector": {},
			"policyType": ["Egress"],
		},
	}

	count(r) == 0
}

test_networkpolicy_with_deny_all_ingress_pod_selector {
	r := deny with input as {
		"apiVersion": "networking.k8s.io/v1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "deny-all-ingress"},
		"spec": {
			"podSelector": {},
			"policyType": ["Ingress"],
		},
	}

	count(r) == 0
}
