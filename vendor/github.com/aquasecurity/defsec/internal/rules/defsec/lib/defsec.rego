package lib.result

new(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", object.get(metadata, "StartLine", 0)),
		"endline": object.get(metadata, "endline", object.get(metadata, "EndLine", 0)),
		"filepath": object.get(metadata, "filepath", object.get(metadata, "Path", "")),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}
