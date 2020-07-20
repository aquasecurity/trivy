package trivy

import data.lib.trivy

default allow = false

nvd_v3_vector = v {
	v := input.CVSS.nvd.v3
}

# Accept a vulnerability which requires high privilege
allow {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.PrivilegesRequired == "High"
}

# Accept a vulnerability which requires user interaction
allow {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.UserInteraction == "Required"
}

allow {
	input.PkgName == "openssl"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	allow_attack_vectors := {"Physical", "Local"}
	cvss_vector.AttackVector == allow_attack_vectors[_]
}

allow {
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

allow {
	input.PkgName == "bash"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	allow_attack_vectors := {"Physical", "Local", "Adjacent"}
	cvss_vector.AttackVector == allow_attack_vectors[_]

	# Evaluate severity
	input.Severity == {"LOW", "MEDIUM", "HIGH"}[_]
}

allow {
	input.PkgName == "django"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate Attack Vector
	allow_attack_vectors := {"Physical", "Local"}
	cvss_vector.AttackVector == allow_attack_vectors[_]

	# Evaluate severity
	input.Severity == {"LOW", "MEDIUM"}[_]

	# Evaluate CWE-ID
	deny_cwe_ids := {
		"CWE-89", # SQL Injection
		"CWE-78", # OS Command Injection
	}

	count({x | x := input.CweIDs[_]; x == deny_cwe_ids[_]}) == 0
}

allow {
	input.PkgName == "jquery"

	# Split CVSSv3 vector
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)

	# Evaluate CWE-ID
	deny_cwe_ids := {"CWE-79"} # XSS
	count({x | x := input.CweIDs[_]; x == deny_cwe_ids[_]}) == 0
}
