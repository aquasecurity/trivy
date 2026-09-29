package trivy

ignore {
    input.Type == "license"
	input.PkgName == "foo"
}

ignore {
    input.Type == "vulnerability"
    input.PkgName == "bar"
}