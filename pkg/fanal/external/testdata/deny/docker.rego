package testdata.xyz_200

__rego_metadata__ := {
	"id": "XYZ-200",
	"title": "Old FROM",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Docker Security Check",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
    stage := input.Stages[_]
    stage.Name == "alpine:3.10"
	msg := "Old image"
	res := {
	    "msg": msg,
	    "startline": 1,
	    "endline": 2,
	}
}
