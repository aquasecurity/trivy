package types

// DetectionPriority represents the priority of detection
type DetectionPriority string

// PriorityPrecise tries to minimize false positives
const PriorityPrecise DetectionPriority = "precise"

// PriorityCoverage tries to minimize false negatives
const PriorityCoverage DetectionPriority = "coverage"
