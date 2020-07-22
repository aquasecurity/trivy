package trivy

import data.lib.trivy

default ignore = false

ignore_pkgs := {"bash", "bind-license", "rpm", "vim", "vim-minimal"}

ignore_severities := {"LOW", "MEDIUM"}

nvd_v3_vector = v {
	v := input.CVSS.nvd.v3
}

ignore {
	input.PkgName == ignore_pkgs[_]
}

ignore {
	input.Severity == ignore_severities[_]
}

# Ignore a vulnerability which is not remotely exploitable
ignore {
	cvss_vector := trivy.parse_cvss_vector_v3(nvd_v3_vector)
	cvss_vector.AttackVector != "Network"
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

# Ignore CSRF
ignore {
	# https://cwe.mitre.org/data/definitions/352.html
	input.CweIDs[_] == "CWE-352"
}
