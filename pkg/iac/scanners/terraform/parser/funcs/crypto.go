// Copied from github.com/hashicorp/terraform/internal/lang/funcs
package funcs

import (
	"crypto/md5" // nolint: gosec
	"crypto/rsa"
	"crypto/sha1" // nolint: gosec
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"strings"

	uuidv5 "github.com/google/uuid"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/gocty"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

var UUIDFunc = function.New(&function.Spec{
	Params:       []function.Parameter{},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		result, err := uuid.GenerateUUID()
		if err != nil {
			return cty.UnknownVal(cty.String), err
		}
		return cty.StringVal(result), nil
	},
})

var UUIDV5Func = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "namespace",
			Type: cty.String,
		},
		{
			Name: "name",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		var namespace uuidv5.UUID
		switch {
		case args[0].AsString() == "dns":
			namespace = uuidv5.NameSpaceDNS
		case args[0].AsString() == "url":
			namespace = uuidv5.NameSpaceURL
		case args[0].AsString() == "oid":
			namespace = uuidv5.NameSpaceOID
		case args[0].AsString() == "x500":
			namespace = uuidv5.NameSpaceX500
		default:
			if namespace, err = uuidv5.Parse(args[0].AsString()); err != nil {
				return cty.UnknownVal(cty.String), fmt.Errorf("uuidv5() doesn't support namespace %s (%v)", args[0].AsString(), err)
			}
		}
		val := args[1].AsString()
		return cty.StringVal(uuidv5.NewSHA1(namespace, []byte(val)).String()), nil
	},
})

// Base64Sha256Func constructs a function that computes the SHA256 hash of a given string
// and encodes it with Base64.
var Base64Sha256Func = makeStringHashFunction(sha256.New, base64.StdEncoding.EncodeToString)

// MakeFileBase64Sha256Func constructs a function that is like Base64Sha256Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileBase64Sha256Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, sha256.New, base64.StdEncoding.EncodeToString)
}

// Base64Sha512Func constructs a function that computes the SHA256 hash of a given string
// and encodes it with Base64.
var Base64Sha512Func = makeStringHashFunction(sha512.New, base64.StdEncoding.EncodeToString)

// MakeFileBase64Sha512Func constructs a function that is like Base64Sha512Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileBase64Sha512Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, sha512.New, base64.StdEncoding.EncodeToString)
}

// BcryptFunc constructs a function that computes a hash of the given string using the Blowfish cipher.
var BcryptFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "str",
			Type: cty.String,
		},
	},
	VarParam: &function.Parameter{
		Name: "cost",
		Type: cty.Number,
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		defaultCost := 10

		if len(args) > 1 {
			var val int
			if err := gocty.FromCtyValue(args[1], &val); err != nil {
				return cty.UnknownVal(cty.String), err
			}
			defaultCost = val
		}

		if len(args) > 2 {
			return cty.UnknownVal(cty.String), errors.New("bcrypt() takes no more than two arguments")
		}

		input := args[0].AsString()
		out, err := bcrypt.GenerateFromPassword([]byte(input), defaultCost)
		if err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("error occurred generating password %s", err.Error())
		}

		return cty.StringVal(string(out)), nil
	},
})

// Md5Func constructs a function that computes the MD5 hash of a given string and encodes it with hexadecimal digits.
var Md5Func = makeStringHashFunction(md5.New, hex.EncodeToString)

// MakeFileMd5Func constructs a function that is like Md5Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileMd5Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, md5.New, hex.EncodeToString)
}

// RsaDecryptFunc constructs a function that decrypts an RSA-encrypted ciphertext.
var RsaDecryptFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{
			Name: "ciphertext",
			Type: cty.String,
		},
		{
			Name: "privatekey",
			Type: cty.String,
		},
	},
	Type:         function.StaticReturnType(cty.String),
	RefineResult: refineNotNull,
	Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
		s := args[0].AsString()
		key := args[1].AsString()

		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return cty.UnknownVal(cty.String), function.NewArgErrorf(0, "failed to decode input %q: cipher text must be base64-encoded", s)
		}

		rawKey, err := ssh.ParseRawPrivateKey([]byte(key))
		if err != nil {
			var errStr string
			switch e := err.(type) {
			case asn1.SyntaxError:
				errStr = strings.ReplaceAll(e.Error(), "asn1: syntax error", "invalid ASN1 data in the given private key")
			case asn1.StructuralError:
				errStr = strings.ReplaceAll(e.Error(), "asn1: structure error", "invalid ASN1 data in the given private key")
			default:
				errStr = fmt.Sprintf("invalid private key: %s", e)
			}
			return cty.UnknownVal(cty.String), function.NewArgErrorf(1, errStr)
		}
		privateKey, ok := rawKey.(*rsa.PrivateKey)
		if !ok {
			return cty.UnknownVal(cty.String), function.NewArgErrorf(1, "invalid private key type %t", rawKey)
		}

		out, err := rsa.DecryptPKCS1v15(nil, privateKey, b)
		if err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("failed to decrypt: %s", err)
		}

		return cty.StringVal(string(out)), nil
	},
})

// Sha1Func constructs a function that computes the SHA1 hash of a given string
// and encodes it with hexadecimal digits.
var Sha1Func = makeStringHashFunction(sha1.New, hex.EncodeToString)

// MakeFileSha1Func constructs a function that is like Sha1Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha1Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, sha1.New, hex.EncodeToString)
}

// Sha256Func constructs a function that computes the SHA256 hash of a given string
// and encodes it with hexadecimal digits.
var Sha256Func = makeStringHashFunction(sha256.New, hex.EncodeToString)

// MakeFileSha256Func constructs a function that is like Sha256Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha256Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, sha256.New, hex.EncodeToString)
}

// Sha512Func constructs a function that computes the SHA512 hash of a given string
// and encodes it with hexadecimal digits.
var Sha512Func = makeStringHashFunction(sha512.New, hex.EncodeToString)

// MakeFileSha512Func constructs a function that is like Sha512Func but reads the
// contents of a file rather than hashing a given literal string.
func MakeFileSha512Func(target fs.FS, baseDir string) function.Function {
	return makeFileHashFunction(target, baseDir, sha512.New, hex.EncodeToString)
}

func makeStringHashFunction(hf func() hash.Hash, enc func([]byte) string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "str",
				Type: cty.String,
			},
		},
		Type:         function.StaticReturnType(cty.String),
		RefineResult: refineNotNull,
		Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
			s := args[0].AsString()
			h := hf()
			h.Write([]byte(s))
			rv := enc(h.Sum(nil))
			return cty.StringVal(rv), nil
		},
	})
}

func makeFileHashFunction(target fs.FS, baseDir string, hf func() hash.Hash, enc func([]byte) string) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{
				Name: "path",
				Type: cty.String,
			},
		},
		Type:         function.StaticReturnType(cty.String),
		RefineResult: refineNotNull,
		Impl: func(args []cty.Value, retType cty.Type) (ret cty.Value, err error) {
			path := args[0].AsString()
			f, err := openFile(target, baseDir, path)
			if err != nil {
				return cty.UnknownVal(cty.String), err
			}
			defer f.Close()

			h := hf()
			_, err = io.Copy(h, f)
			if err != nil {
				return cty.UnknownVal(cty.String), err
			}
			rv := enc(h.Sum(nil))
			return cty.StringVal(rv), nil
		},
	})
}
