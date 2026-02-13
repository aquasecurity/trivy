package types

// OWASPRating represents an OWASP Risk Rating from a VEX document.
// This provides a contextual risk score that considers the specific deployment environment,
// calculated using the OWASP Risk Rating methodology.
// See: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
type OWASPRating struct {
	// Score is the numerical risk score (0-81 scale)
	// Calculated as: Likelihood × Impact
	Score float64 `json:"score,omitempty"`

	// Severity is the severity level based on the score
	// Thresholds: 0-9 (low), 10-39 (medium), 40-59 (high), 60-81 (critical)
	Severity string `json:"severity,omitempty"`

	// Vector is the OWASP Risk Rating vector string that produced this rating
	// Format: "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
	Vector string `json:"vector,omitempty"`
}
