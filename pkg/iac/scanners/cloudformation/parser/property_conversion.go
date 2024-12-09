package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
	"github.com/aquasecurity/trivy/pkg/log"
)

func (p *Property) IsConvertableTo(conversionType cftypes.CfType) bool {
	if p.IsNil() {
		return false
	}

	switch conversionType {
	case cftypes.Int:
		return p.isConvertableToInt()
	case cftypes.Bool:
		return p.isConvertableToBool()
	case cftypes.String:
		return p.isConvertableToString()
	}
	return false
}

func (p *Property) isConvertableToString() bool {
	switch p.Type() {
	case cftypes.Map:
		return false
	case cftypes.List:
		for _, p := range p.AsList() {
			if !p.IsString() {
				return false
			}
		}
	}
	return true
}

func (p *Property) isConvertableToBool() bool {
	switch p.Type() {
	case cftypes.String:
		return p.EqualTo("true", IgnoreCase) || p.EqualTo("false", IgnoreCase) ||
			p.EqualTo("1", IgnoreCase) || p.EqualTo("0", IgnoreCase)

	case cftypes.Int:
		return p.EqualTo(1) || p.EqualTo(0)
	case cftypes.Bool:
		return true
	}
	return false
}

func (p *Property) isConvertableToInt() bool {
	switch p.Type() {
	case cftypes.String:
		if _, err := strconv.Atoi(p.AsString()); err == nil {
			return true
		}
	case cftypes.Bool, cftypes.Int:
		return true
	}
	return false
}

func (p *Property) ConvertTo(conversionType cftypes.CfType) *Property {
	if p.IsNil() {
		return nil
	}

	if p.Type() == conversionType {
		return p
	}

	if !p.IsConvertableTo(conversionType) {
		log.Debug("Failed to convert property",
			log.String("from", string(p.Type())),
			log.String("to", string(conversionType)),
			log.Any("range", p.Range().String()),
		)
		return p
	}
	switch conversionType {
	case cftypes.Int:
		return p.convertToInt()
	case cftypes.Bool:
		return p.convertToBool()
	case cftypes.String:
		return p.convertToString()
	}
	return p
}

func (p *Property) convertToString() *Property {
	switch p.Type() {
	case cftypes.Int:
		return p.deriveResolved(cftypes.String, strconv.Itoa(p.AsInt()))
	case cftypes.Bool:
		return p.deriveResolved(cftypes.String, fmt.Sprintf("%v", p.AsBool()))
	case cftypes.List:
		var parts []string
		for _, property := range p.AsList() {
			parts = append(parts, property.AsString())
		}
		return p.deriveResolved(cftypes.String, fmt.Sprintf("[%s]", strings.Join(parts, ", ")))
	}
	return p
}

func (p *Property) convertToBool() *Property {
	switch p.Type() {
	case cftypes.String:
		if p.EqualTo("true", IgnoreCase) || p.EqualTo("1") {
			return p.deriveResolved(cftypes.Bool, true)
		}
		if p.EqualTo("false", IgnoreCase) || p.EqualTo("0") {
			return p.deriveResolved(cftypes.Bool, false)
		}
	case cftypes.Int:
		if p.EqualTo(1) {
			return p.deriveResolved(cftypes.Bool, true)
		}
		if p.EqualTo(0) {
			return p.deriveResolved(cftypes.Bool, false)
		}
	}
	return p
}

func (p *Property) convertToInt() *Property {
	//
	switch p.Type() {
	case cftypes.String:
		if val, err := strconv.Atoi(p.AsString()); err == nil {
			return p.deriveResolved(cftypes.Int, val)
		}
	case cftypes.Bool:
		if p.IsTrue() {
			return p.deriveResolved(cftypes.Int, 1)
		}
		return p.deriveResolved(cftypes.Int, 0)
	}
	return p
}
