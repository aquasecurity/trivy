package main.yaml.xyz_123

__rego_metadata__ := {
    "id": "XYZ-123",
    "title": "Bad YAML",
    "version": "v1.0.0",
    "severity": "CRITICAL",
    "type": "YAML Security Check",
}

deny[msg]{
    msg := "bad"
}