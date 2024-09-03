package types

// DetectionPriority represents the priority of detection
type DetectionPriority string

// PriorityPrecise tries to minimize false positives
const PriorityPrecise DetectionPriority = "precise"

// PriorityComprehensive tries to minimize false negatives
const PriorityComprehensive DetectionPriority = "comprehensive"
