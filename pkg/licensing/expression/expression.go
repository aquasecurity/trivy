package expression

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/licensing/expression/lexer"
	"github.com/aquasecurity/trivy/pkg/licensing/expression/parser"
)

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

// NormalizeForSPDX is normalized license-id replace ' ' to '-'.
// SPDX license MUST NOT be white space between a license-id.
// There MUST be white space on either side of the operator "WITH".
// ref: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions
func NormalizeForSPDX(name string) string {
	OperatorWith := " WITH "
	i := strings.Index(strings.ToUpper(name), OperatorWith)
	if i < 0 {
		return strings.Replace(name, " ", "-", -1)
	}

	// Convert "WITH" expression split by " " to "-".
	// examples:
	// 	GPL-2+ with distribution exception => GPL-2+ with distribution-exception
	//  GPL-2 with Linux-syscall-note exception => GPL-2 with Linux-syscall-note-exception
	//  AFL 2.0 with Linux-syscall-note exception => AFL-2.0 with Linux-syscall-note-exception
	withSection := strings.Replace(name[i+len(OperatorWith):], " ", "-", -1)
	if i > 0 {
		return strings.Replace(name[:i], " ", "-", -1) + OperatorWith + withSection
	}
	return name
}
