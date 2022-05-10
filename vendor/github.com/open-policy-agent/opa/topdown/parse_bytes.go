// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
)

const (
	none uint64 = 1 << (10 * iota)
	ki
	mi
	gi
	ti
	pi
	ei

	kb uint64 = 1000
	mb        = kb * 1000
	gb        = mb * 1000
	tb        = gb * 1000
	pb        = tb * 1000
	eb        = pb * 1000
)

func parseNumBytesError(msg string) error {
	return fmt.Errorf("%s error: %s", ast.UnitsParseBytes.Name, msg)
}

func errUnitNotRecognized(unit string) error {
	return parseNumBytesError(fmt.Sprintf("byte unit %s not recognized", unit))
}

var (
	errNoAmount       = parseNumBytesError("no byte amount provided")
	errNumConv        = parseNumBytesError("could not parse byte amount to a number")
	errIncludesSpaces = parseNumBytesError("spaces not allowed in resource strings")
)

func builtinNumBytes(bctx BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	var m big.Float

	raw, err := builtins.StringOperand(operands[0].Value, 1)
	if err != nil {
		return err
	}

	s := formatString(raw)

	if strings.Contains(s, " ") {
		return errIncludesSpaces
	}

	num, unit := extractNumAndUnit(s)
	if num == "" {
		return errNoAmount
	}

	switch unit {
	case "":
		m.SetUint64(none)
	case "kb", "k":
		m.SetUint64(kb)
	case "kib", "ki":
		m.SetUint64(ki)
	case "mb", "m":
		m.SetUint64(mb)
	case "mib", "mi":
		m.SetUint64(mi)
	case "gb", "g":
		m.SetUint64(gb)
	case "gib", "gi":
		m.SetUint64(gi)
	case "tb", "t":
		m.SetUint64(tb)
	case "tib", "ti":
		m.SetUint64(ti)
	case "pb", "p":
		m.SetUint64(pb)
	case "pib", "pi":
		m.SetUint64(pi)
	case "eb", "e":
		m.SetUint64(eb)
	case "eib", "ei":
		m.SetUint64(ei)
	default:
		return errUnitNotRecognized(unit)
	}

	numFloat, ok := new(big.Float).SetString(num)
	if !ok {
		return errNumConv
	}

	var total big.Int
	numFloat.Mul(numFloat, &m).Int(&total)
	return iter(ast.NewTerm(builtins.IntToNumber(&total)))
}

// Makes the string lower case and removes quotation marks
func formatString(s ast.String) string {
	str := string(s)
	lower := strings.ToLower(str)
	return strings.Replace(lower, "\"", "", -1)
}

// Splits the string into a number string à la "10" or "10.2" and a unit
// string à la "gb" or "MiB" or "foo". Either can be an empty string
// (error handling is provided elsewhere).
func extractNumAndUnit(s string) (string, string) {
	isNum := func(r rune) bool {
		return unicode.IsDigit(r) || r == '.'
	}

	firstNonNumIdx := -1
	for idx, r := range s {
		if !isNum(r) {
			firstNonNumIdx = idx
			break
		}
	}

	if firstNonNumIdx == -1 { // only digits and '.'
		return s, ""
	}
	if firstNonNumIdx == 0 { // only units (starts with non-digit)
		return "", s
	}

	return s[0:firstNonNumIdx], s[firstNonNumIdx:]
}

func init() {
	RegisterBuiltinFunc(ast.UnitsParseBytes.Name, builtinNumBytes)
}
