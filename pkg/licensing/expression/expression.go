package expression

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/licensing/expression/lexer"
	"github.com/aquasecurity/trivy/pkg/licensing/expression/parser"
)

type Operator string

const (
	AND  Operator = "AND"
	OR   Operator = "OR"
	WITH Operator = "WITH"
)

func (o Operator) String() string {
	return fmt.Sprintf(" %s ", string(o))
}

func Normalize(license string, fn ...parser.NormalizeFunc) string {
	lex := lexer.New(license)
	licenseParser := parser.New(lex).RegisterNormalizeFunc(
		fn...,
	)
	expression, err := licenseParser.Parse()
	if err != nil {
		return license
	}
	return licenseParser.Normalize(expression)
}

func Join(elems []string, sep Operator) string {
	var licenses []string
	for i, license := range elems {
		var mid Operator
		if sep == AND {
			mid = OR
		} else if sep == OR {
			mid = AND
		}

		if i != 0 && strings.Contains(strings.ToUpper(license), mid.String()) {
			license = fmt.Sprintf("(%s)", license)
		}
		licenses = append(licenses, license)
	}

	return strings.Join(licenses, sep.String())
}

// NormalizeForSPDX is normalized license-id replace ' ' to '-'.
// SPDX license MUST NOT be white space between a license-id.
// There MUST be white space on either side of the operator "WITH".
// ref: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions
func NormalizeForSPDX(name string) string {
	i := strings.Index(strings.ToUpper(name), WITH.String())
	if i < 0 {
		return strings.Replace(name, " ", "-", -1)
	}

	// Convert "WITH" expression split by " " to "-".
	// examples:
	// 	GPL-2+ with distribution exception => GPL-2+ with distribution-exception
	//  GPL-2 with Linux-syscall-note exception => GPL-2 with Linux-syscall-note-exception
	//  AFL 2.0 with Linux-syscall-note exception => AFL-2.0 with Linux-syscall-note-exception
	withSection := strings.Replace(name[i+len(WITH.String()):], " ", "-", -1)
	if i > 0 {
		return strings.Replace(name[:i], " ", "-", -1) + WITH.String() + withSection
	}
	return name
}
