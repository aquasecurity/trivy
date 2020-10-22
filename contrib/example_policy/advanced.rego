package trivy

import data.lib.trivy

default ignore = false

nvd_v3_vector = v {
	v := input.CVSS.nvd.v3
}

# Ignore a vulnerability which requires high privilege
ignore {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.PrivilegesRequired == "High"
}

# Ignore a vulnerability which requires user interaction
ignore {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.UserInteraction == "Required"
}

ignore {
	input.PkgName == "openssl"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	ignore_attack_vectors := {"Physical", "Local"}
	cvss_vector.AttackVector == ignore_attack_vectors[_]
}

ignore {
	input.PkgName == "openssl"

	# Evaluate severity
	input.Severity == {"LOW", "MEDIUM", "HIGH"}[_]

	# Evaluate CWE-ID
	deny_cwe_ids := {
		"CWE-119", # Improper Restriction of Operations within the Bounds of a Memory Buffer
		"CWE-200", # Exposure of Sensitive Information to an Unauthorized Actor
	}

	count({x | x := input.CweIDs[_]; x == deny_cwe_ids[_]}) == 0
}

ignore {
	input.PkgName == "bash"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	ignore_attack_vectors := {"Physical", "Local", "Adjacent"}
	cvss_vector.AttackVector == ignore_attack_vectors[_]

	# Evaluate severity
	input.Severity == {"LOW", "MEDIUM", "HIGH"}[_]
}

ignore {
	input.PkgName == "django"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	ignore_attack_vectors := {"Physical", "Local"}
	cvss_vector.AttackVector == ignore_attack_vectors[_]

	# Evaluate severity
	input.Severity == {"LOW", "MEDIUM"}[_]

	# Evaluate CWE-ID
	deny_cwe_ids := {
		"CWE-89", # SQL Injection
		"CWE-78", # OS Command Injection
	}

	count({x | x := input.CweIDs[_]; x == deny_cwe_ids[_]}) == 0
}

ignore {
	input.PkgName == "jquery"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate CWE-ID
	deny_cwe_ids := {"CWE-79"} # XSS
	count({x | x := input.CweIDs[_]; x == deny_cwe_ids[_]}) == 0
}
