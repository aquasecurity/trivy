package common

import (
	"strconv"
	"strings"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type PortRange struct {
	Metadata iacTypes.Metadata
	Start    iacTypes.IntValue
	End      iacTypes.IntValue
}

func NewPortRange(start, end int, meta iacTypes.Metadata) PortRange {
	return PortRange{
		Metadata: meta,
		Start:    iacTypes.Int(start, meta),
		End:      iacTypes.Int(end, meta),
	}
}

func FullPortRange(meta iacTypes.Metadata) PortRange {
	return NewPortRange(0, 65535, meta)
}

func InvalidPortRange(meta iacTypes.Metadata) PortRange {
	return NewPortRange(-1, -1, meta)
}

func (r PortRange) Valid() bool {
	return !r.Start.EqualTo(-1) && !r.End.EqualTo(-1)
}

type parseConfig struct {
	allowWildcard bool
}

type ParseOption func(*parseConfig)

func WithWildcard() ParseOption {
	return func(cfg *parseConfig) {
		cfg.allowWildcard = true
	}
}

func ParsePortRange(input string, meta iacTypes.Metadata, opts ...ParseOption) PortRange {
	cfg := &parseConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	input = strings.TrimSpace(input)

	switch {
	case input == "*" && cfg.allowWildcard:
		return FullPortRange(meta)
	case strings.Contains(input, "-"):
		parts := strings.SplitN(input, "-", 2)
		if len(parts) != 2 {
			return InvalidPortRange(meta)
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return InvalidPortRange(meta)
		}
		return NewPortRange(start, end, meta)

	default:
		val, err := strconv.Atoi(input)
		if err != nil {
			return InvalidPortRange(meta)
		}
		return NewPortRange(val, val, meta)
	}
}
