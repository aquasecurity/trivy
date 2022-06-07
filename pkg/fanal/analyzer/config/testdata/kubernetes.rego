package main.kubernetes.xyz_100

__rego_metadata__ := {
    "id": "XYZ-100",
    "title": "Bad Kubernetes Replicas",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "Kubernetes Security Check",
}

deny[msg] {
	rpl = input.spec.replicas
	rpl > 3
	msg = sprintf("too many replicas: %d", [rpl])
}