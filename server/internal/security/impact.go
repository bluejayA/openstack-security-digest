package security

// Impact is the operational severity category assigned to an advisory.
type Impact string

const (
	ImpactCritical Impact = "Critical"
	ImpactHigh     Impact = "High"
	ImpactMedium   Impact = "Medium"
	ImpactLow      Impact = "Low"
	ImpactUnknown  Impact = "Unknown"
)

// ParseImpact converts a string (e.g. a configured threshold) to an Impact,
// defaulting to High for unrecognized values.
func ParseImpact(s string) Impact {
	switch Impact(s) {
	case ImpactCritical:
		return ImpactCritical
	case ImpactHigh:
		return ImpactHigh
	case ImpactMedium:
		return ImpactMedium
	case ImpactLow:
		return ImpactLow
	default:
		return ImpactHigh
	}
}

// Rank returns a sortable weight (higher = more severe).
func (i Impact) Rank() int {
	switch i {
	case ImpactCritical:
		return 4
	case ImpactHigh:
		return 3
	case ImpactMedium:
		return 2
	case ImpactLow:
		return 1
	default:
		return 0
	}
}
