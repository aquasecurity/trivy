package trivy

severities := {"HIGH", "CRITICAL"}
ignore_pkgs := {"bash", "bind-license", "rpm", "vim", "vim-minimal"}

filter[vuln] {
	vuln := input_vulnerabilities[_]

	# Evaluate CVSS vector
    not high_privilege_required[vuln]
    not require_user_interaction[vuln]
	attack_vector_is_network[vuln]

	# Evaluate severity
	severities[vuln.Severity]

    # Evaluate package name
    not ignore_pkgs[vuln.PkgName]
}

input_vulnerabilities[v] {
	v := input[_]
}

attack_vector_is_network[v] {
	v := input_vulnerabilities[_]
    vector := split_cvss_vector(v.CVSS[_])
    vector[1] == "AV:N"
}

high_privilege_required[v] {
	v := input_vulnerabilities[_]
    vector := split_cvss_vector(v.CVSS[_])
    vector[3] == "PR:H"
}

require_user_interaction[v] {
	v := input_vulnerabilities[_]
    vector := split_cvss_vector(v.CVSS[_])
    vector[4] == "UI:R"
}


split_cvss_vector(cvss) = vector {
	vector := split(cvss.V3Vector, "/")
}