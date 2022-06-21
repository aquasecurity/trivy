package user.something

__rego_metadata__ := {
	"id": "TEST001",
	"avd_id": "AVD-TEST-0001",
	"title": "Test policy",
	"short_code": "no-buckets",
	"severity": "LOW",
	"description": "This is a test policy.",
	"recommended_actions": "Have a cup of tea.",
	"url": "https://trivy.dev/",
}

# taken from defsec rego lib to mimic behaviour
result(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", 0),
		"endline": object.get(metadata, "endline", 0),
		"filepath": object.get(metadata, "filepath", ""),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}

deny[res] {
    bucket := input.aws.s3.buckets[_]
    true == false
    res := result("No buckets allowed!", bucket)
}