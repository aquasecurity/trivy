package testdata.docker.id_300

deny[res] {
  input.kind = "Deployment"
  res := {"type": "Docker Check", "id": "ID-300", "msg": "deny", "severity": "HIGH"}
}
