package trivy

deny_policy := {
    {
    	"PkgName": "openssl",
        "AttackVector": {"AV:A", "AV:N"},
        "CweIDs": {
            "CWE-119", # Improper Restriction of Operations within the Bounds of a Memory Buffer
        	"CWE-200"  # Exposure of Sensitive Information to an Unauthorized Actor
        },
        "Severity": {"MEDIUM", "HIGH", "CRITICAL"}
    },
    {
    	"PkgName": "bash",
        "AttackVector": {"AV:N"},
        "CweIDs": {},
        "Severity": {"CRITICAL"}
    },
	{
    	"PkgName": "tar",
        "AttackVector": {"AV:L", "AV:A", "AV:N"},
        "CweIDs": {
        	"CWE-22" # Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
        },
        "Severity": {"MEDIUM", "HIGH", "CRITICAL"}
    },
    {
    	"PkgName": "django",
        "CweIDs": {
        	"CWE-89", # SQL Injection
            "CWE-78"  # OS Command Injection
        },
        "AttackVector": {"AV:N"},
        "Severity": {"MEDIUM", "HIGH", "CRITICAL"}
    },
    {
    	"PkgName": "pyyaml",
        "CweIDs": {
        	"CWE-20" # Improper Input Validation
        },
        "AttackVector": {"AV:N"},
        "Severity": {"MEDIUM", "HIGH", "CRITICAL"}
    },
    {
    	"PkgName": "jquery",
        "CweIDs": {
        	"CWE-79" # XSS
        },
        "AttackVector": {"AV:N"},
        "Severity": {"HIGH", "CRITICAL"}
    }
}

filter[vuln] {
	vuln := input_vulnerabilities[_]

    # Even if the severity is CRITICAL, a vulnerability that requires privileges should be ignored.
    not high_privilege_required[vuln]

    # Even if the severity is CRITICAL, a vulnerability that user interaction should be ignored.
    not require_user_interaction[vuln]

    policy := deny_policy[_]
    vuln.PkgName == policy.PkgName
    vuln.Severity == policy.Severity[_]

    # Check if this vulnerability has CWE-ID which should be handled.
    blocked_cwe_id[[vuln.PkgName, vuln.VulnerabilityID]]

    # Check if this vulnerability has Attack Vector which should be handled.
    split_cvss_vector(vuln.CVSS[_])[1] == policy.AttackVector[_]
}

input_vulnerabilities[v] {
	v := input[_]
}

# If CweIDs is not specified, all vulnerabilities should be blocked.
blocked_cwe_id[[v.PkgName, v.VulnerabilityID]] {
    policy := deny_policy[_]
    v := input_vulnerabilities[_]
    v.PkgName == policy.PkgName
    count(policy.CweIDs) == 0
}

# If CweIDs is specified, only vulnerabilities matching the specified CWE-IDs are blocked.
blocked_cwe_id[[v.PkgName, v.VulnerabilityID]] {
    policy := deny_policy[_]
    v := input_vulnerabilities[_]
    v.PkgName == policy.PkgName
    v.CweIDs[_] == policy.CweIDs[_]
}

# The vulnerability which requires a high privilege should be ignored.
high_privilege_required[v] {
	v := input_vulnerabilities[_]
    vector := split_cvss_vector(v.CVSS[_])
    vector[3] == "PR:H"
}

# The vulnerability which requires a user interaction should be ignored.
require_user_interaction[v] {
	v := input_vulnerabilities[_]
    vector := split_cvss_vector(v.CVSS[_])
    vector[4] == "UI:R"
}

split_cvss_vector(cvss) = vector {
	vector := split(cvss.V3Vector, "/")
}
