package testdata.kubernetes.id_200

__rego_metadata__ := {
    "id": "ID-200",
    "title": "Bad Deployment",
    "version": "v1.0.0",
    "severity": "CRITICAL",
    "type": "Kubernetes Security Check",
}

deny[msg] {
  input.kind == "Deployment"
  msg := "deny"
}
