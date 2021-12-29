package result

const (
	module = `
package lib.trivy

parse_cvss_vector_v3(cvss) = vector {
	s := split(cvss, "/")
	vector := {
		"AttackVector": attack_vector[s[1]],
		"AttackComplexity": attack_complexity[s[2]],
		"PrivilegesRequired": privileges_required[s[3]],
		"UserInteraction": user_interaction[s[4]],
		"Scope": scope[s[5]],
		"Confidentiality": confidentiality[s[6]],
		"Integrity": integrity[s[7]],
		"Availability": availability[s[8]],
	}
}

attack_vector := {
	"AV:N": "Network",
	"AV:A": "Adjacent",
	"AV:L": "Local",
	"AV:P": "Physical",
}

attack_complexity := {
	"AC:L": "Low",
	"AC:H": "High",
}

privileges_required := {
	"PR:N": "None",
	"PR:L": "Low",
	"PR:H": "High",
}

user_interaction := {
	"UI:N": "None",
	"UI:R": "Required",
}

scope := {
	"S:U": "Unchanged",
	"S:C": "Changed",
}

confidentiality := {
	"C:N": "None",
	"C:L": "Low",
	"C:H": "High",
}

integrity := {
	"I:N": "None",
	"I:L": "Low",
	"I:H": "High",
}

availability := {
	"A:N": "None",
	"A:L": "Low",
	"A:H": "High",
}
`
)
