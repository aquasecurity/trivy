package trivy

import data.lib.trivy

default allow = false

ignore_pkgs := {"bash", "bind-license", "rpm", "vim", "vim-minimal"}

allow_severities := {"LOW", "MEDIUM"}

nvd_v3_vector = v {
	v := input.CVSS.nvd.v3
}

allow {
	input.PkgName == ignore_pkgs[_]
}

allow {
	input.Severity == allow_severities[_]
}

# Accept a vulnerability which is not remotely exploitable
allow {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.AttackVector != "Network"
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

# Accept CSRF
allow {
	# https://cwe.mitre.org/data/definitions/352.html
	input.CweIDs[_] == "CWE-352"
}
