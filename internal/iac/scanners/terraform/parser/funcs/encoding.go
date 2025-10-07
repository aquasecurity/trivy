// Copied from github.com/hashicorp/terraform/internal/lang/funcs
package funcs

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"unicode/utf8"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"golang.org/x/text/encoding/ianaindex"
)

// Base64DecodeFunc constructs a function that decodes a string containing a base64 sequence.
var Base64DecodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name:        "str",
			Type:        cty.String,
			AllowMarked: true,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		str, strMarks := args[0].Unmark()
		s := str.AsString()
		sDec, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to decode base64 data %s", redactIfSensitive(s, strMarks))
		}
		if !utf8.Valid([]byte(sDec)) {
			log.Printf("[DEBUG] the result of decoding the provided string is not valid UTF-8: %s", redactIfSensitive(sDec, strMarks))
			return cty.UnknownVal(cty.String), errors.New("the result of decoding the provided string is not valid UTF-8")
		}
		return cty.StringVal(string(sDec)).WithMarks(strMarks), nil
	},
})

// Base64EncodeFunc constructs a function that encodes a string to a base64 sequence.
var Base64EncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "str",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})

// TextEncodeBase64Func constructs a function that encodes a string to a target encoding and then to a base64 sequence.
var TextEncodeBase64Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "string",
			Type: cty.String,
		},
		{
			Name: "encoding",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		encoding, err := ianaindex.IANA.Encoding(args[1].AsString())
		if err != nil || encoding == nil {
			return cty.UnknownVal(cty.String), function.NewArgErrorf(1, "%q is not a supported IANA encoding name or alias in this Terraform version", args[1].AsString())
		}

		encName, err := ianaindex.IANA.Name(encoding)
		if err != nil { // would be weird, since we just read this encoding out
			encName = args[1].AsString()
		}

		encoder := encoding.NewEncoder()
		encodedInput, err := encoder.Bytes([]byte(args[0].AsString()))
		if err != nil {
			// The string representations of "err" disclose implementation
			// details of the underlying library, and the main error we might
			// like to return a special message for is unexported as
			// golang.org/x/text/encoding/internal.RepertoireError, so this
			// is just a generic error message for now.
			//
			// We also don't include the string itself in the message because
			// it can typically be very large, contain newline characters,
			// etc.
			return cty.UnknownVal(cty.String), function.NewArgErrorf(0, "the given string contains characters that cannot be represented in %s", encName)
		}

		return cty.StringVal(base64.StdEncoding.EncodeToString(encodedInput)), nil
	},
})

// TextDecodeBase64Func constructs a function that decodes a base64 sequence to a target encoding.
var TextDecodeBase64Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "source",
			Type: cty.String,
		},
		{
			Name: "encoding",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		encoding, err := ianaindex.IANA.Encoding(args[1].AsString())
		if err != nil || encoding == nil {
			return cty.UnknownVal(cty.String), function.NewArgErrorf(1, "%q is not a supported IANA encoding name or alias in this Terraform version", args[1].AsString())
		}

		encName, err := ianaindex.IANA.Name(encoding)
		if err != nil { // would be weird, since we just read this encoding out
			encName = args[1].AsString()
		}

		s := args[0].AsString()
		sDec, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			switch err := err.(type) {
			case base64.CorruptInputError:
				return cty.UnknownVal(cty.String), function.NewArgErrorf(0, "the given value is has an invalid base64 symbol at offset %d", int(err))
			default:
				return cty.UnknownVal(cty.String), function.NewArgErrorf(0, "invalid source string: %w", err)
			}

		}

		decoder := encoding.NewDecoder()
		decoded, err := decoder.Bytes(sDec)
		if err != nil || bytes.ContainsRune(decoded, '�') {
			return cty.UnknownVal(cty.String), function.NewArgErrorf(0, "the given string contains symbols that are not defined for %s", encName)
		}

		return cty.StringVal(string(decoded)), nil
	},
})

// Base64GzipFunc constructs a function that compresses a string with gzip and then encodes the result in
// Base64 encoding.
var Base64GzipFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "str",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		s := args[0].AsString()

		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		if _, err := gz.Write([]byte(s)); err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to write gzip raw data: %w", err)
		}
		if err := gz.Flush(); err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to flush gzip writer: %w", err)
		}
		if err := gz.Close(); err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to close gzip writer: %w", err)
		}
		return cty.StringVal(base64.StdEncoding.EncodeToString(b.Bytes())), nil
	},
})

// URLEncodeFunc constructs a function that applies URL encoding to a given string.
var URLEncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "str",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(url.QueryEscape(args[0].AsString())), nil
	},
})
