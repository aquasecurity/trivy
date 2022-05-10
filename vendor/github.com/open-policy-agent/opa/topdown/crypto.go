// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package topdown

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/internal/jwx/jwk"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/util"
)

const (
	// blockTypeCertificate indicates this PEM block contains the signed certificate.
	// Exported for tests.
	blockTypeCertificate = "CERTIFICATE"
	// blockTypeCertificateRequest indicates this PEM block contains a certificate
	// request. Exported for tests.
	blockTypeCertificateRequest = "CERTIFICATE REQUEST"
	// blockTypeRSAPrivateKey indicates this PEM block contains a RSA private key.
	// Exported for tests.
	blockTypeRSAPrivateKey = "RSA PRIVATE KEY"
	// blockTypeRSAPrivateKey indicates this PEM block contains a RSA private key.
	// Exported for tests.
	blockTypePrivateKey = "PRIVATE KEY"
)

func builtinCryptoX509ParseCertificates(a ast.Value) (ast.Value, error) {
	input, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	certs, err := getX509CertsFromString(string(input))
	if err != nil {
		return nil, err
	}

	return ast.InterfaceToValue(certs)
}

func builtinCryptoX509ParseAndVerifyCertificates(
	_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {

	a := args[0].Value
	input, err := builtins.StringOperand(a, 1)
	if err != nil {
		return err
	}

	invalid := ast.ArrayTerm(
		ast.BooleanTerm(false),
		ast.NewTerm(ast.NewArray()),
	)

	certs, err := getX509CertsFromString(string(input))
	if err != nil {
		return iter(invalid)
	}

	verified, err := verifyX509CertificateChain(certs)
	if err != nil {
		return iter(invalid)
	}

	value, err := ast.InterfaceToValue(verified)
	if err != nil {
		return err
	}

	valid := ast.ArrayTerm(
		ast.BooleanTerm(true),
		ast.NewTerm(value),
	)

	return iter(valid)
}

func builtinCryptoX509ParseCertificateRequest(a ast.Value) (ast.Value, error) {

	input, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}

	// data to be passed to x509.ParseCertificateRequest
	bytes := []byte(input)

	// if the input is not a PEM string, attempt to decode b64
	if str := string(input); !strings.HasPrefix(str, "-----BEGIN CERTIFICATE REQUEST-----") {
		bytes, err = base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, err
		}
	}

	p, _ := pem.Decode(bytes)
	if p != nil && p.Type != blockTypeCertificateRequest {
		return nil, fmt.Errorf("invalid PEM-encoded certificate signing request")
	}
	if p != nil {
		bytes = p.Bytes
	}

	csr, err := x509.ParseCertificateRequest(bytes)
	if err != nil {
		return nil, err
	}

	bs, err := json.Marshal(csr)
	if err != nil {
		return nil, err
	}

	var x interface{}
	if err := util.UnmarshalJSON(bs, &x); err != nil {
		return nil, err
	}
	return ast.InterfaceToValue(x)
}

func builtinCryptoX509ParseRSAPrivateKey(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {

	a := args[0].Value
	input, err := builtins.StringOperand(a, 1)
	if err != nil {
		return err
	}

	// get the raw private key
	rawKey, err := getRSAPrivateKeyFromString(string(input))
	if err != nil {
		return err
	}

	rsaPrivateKey, err := jwk.New(rawKey)
	if err != nil {
		return err
	}

	jsonKey, err := json.Marshal(rsaPrivateKey)
	if err != nil {
		return err
	}

	var x interface{}
	if err := util.UnmarshalJSON(jsonKey, &x); err != nil {
		return err
	}

	value, err := ast.InterfaceToValue(x)
	if err != nil {
		return err
	}

	return iter(ast.NewTerm(value))
}

func hashHelper(a ast.Value, h func(ast.String) string) (ast.Value, error) {
	s, err := builtins.StringOperand(a, 1)
	if err != nil {
		return nil, err
	}
	return ast.String(h(s)), nil
}

func builtinCryptoMd5(a ast.Value) (ast.Value, error) {
	return hashHelper(a, func(s ast.String) string { return fmt.Sprintf("%x", md5.Sum([]byte(s))) })
}

func builtinCryptoSha1(a ast.Value) (ast.Value, error) {
	return hashHelper(a, func(s ast.String) string { return fmt.Sprintf("%x", sha1.Sum([]byte(s))) })
}

func builtinCryptoSha256(a ast.Value) (ast.Value, error) {
	return hashHelper(a, func(s ast.String) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) })
}

func hmacHelper(args []*ast.Term, iter func(*ast.Term) error, h func() hash.Hash) error {
	a1 := args[0].Value
	message, err := builtins.StringOperand(a1, 1)
	if err != nil {
		return err
	}

	a2 := args[1].Value
	key, err := builtins.StringOperand(a2, 2)
	if err != nil {
		return err
	}

	mac := hmac.New(h, []byte(key))
	mac.Write([]byte(message))
	messageDigest := mac.Sum(nil)

	return iter(ast.StringTerm(fmt.Sprintf("%x", messageDigest)))
}

func builtinCryptoHmacMd5(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	return hmacHelper(args, iter, md5.New)
}

func builtinCryptoHmacSha1(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	return hmacHelper(args, iter, sha1.New)
}

func builtinCryptoHmacSha256(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	return hmacHelper(args, iter, sha256.New)
}

func builtinCryptoHmacSha512(_ BuiltinContext, args []*ast.Term, iter func(*ast.Term) error) error {
	return hmacHelper(args, iter, sha512.New)
}

func init() {
	RegisterFunctionalBuiltin1(ast.CryptoX509ParseCertificates.Name, builtinCryptoX509ParseCertificates)
	RegisterBuiltinFunc(ast.CryptoX509ParseAndVerifyCertificates.Name, builtinCryptoX509ParseAndVerifyCertificates)
	RegisterFunctionalBuiltin1(ast.CryptoMd5.Name, builtinCryptoMd5)
	RegisterFunctionalBuiltin1(ast.CryptoSha1.Name, builtinCryptoSha1)
	RegisterFunctionalBuiltin1(ast.CryptoSha256.Name, builtinCryptoSha256)
	RegisterFunctionalBuiltin1(ast.CryptoX509ParseCertificateRequest.Name, builtinCryptoX509ParseCertificateRequest)
	RegisterBuiltinFunc(ast.CryptoX509ParseRSAPrivateKey.Name, builtinCryptoX509ParseRSAPrivateKey)
	RegisterBuiltinFunc(ast.CryptoHmacMd5.Name, builtinCryptoHmacMd5)
	RegisterBuiltinFunc(ast.CryptoHmacSha1.Name, builtinCryptoHmacSha1)
	RegisterBuiltinFunc(ast.CryptoHmacSha256.Name, builtinCryptoHmacSha256)
	RegisterBuiltinFunc(ast.CryptoHmacSha512.Name, builtinCryptoHmacSha512)
}

func verifyX509CertificateChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) < 2 {
		return nil, builtins.NewOperandErr(1, "must supply at least two certificates to be able to verify")
	}

	// first cert is the root
	roots := x509.NewCertPool()
	roots.AddCert(certs[0])

	// all other certs except the last are intermediates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediates.AddCert(certs[i])
	}

	// last cert is the leaf
	leaf := certs[len(certs)-1]

	// verify the cert chain back to the root
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	chains, err := leaf.Verify(verifyOpts)
	if err != nil {
		return nil, err
	}

	return chains[0], nil
}

func getX509CertsFromString(certs string) ([]*x509.Certificate, error) {
	// if the input is PEM handle that
	if strings.HasPrefix(certs, "-----BEGIN") {
		return getX509CertsFromPem([]byte(certs))
	}

	// assume input is base64 if not PEM
	b64, err := base64.StdEncoding.DecodeString(certs)
	if err != nil {
		return nil, err
	}

	// handle if the decoded base64 contains PEM rather than the expected DER
	if bytes.HasPrefix(b64, []byte("-----BEGIN")) {
		return getX509CertsFromPem(b64)
	}

	// otherwise assume the contents are DER
	return x509.ParseCertificates(b64)
}

func getX509CertsFromPem(pemBlocks []byte) ([]*x509.Certificate, error) {
	var decodedCerts []byte
	for len(pemBlocks) > 0 {
		p, r := pem.Decode(pemBlocks)
		if p != nil && p.Type != blockTypeCertificate {
			return nil, fmt.Errorf("PEM block type is '%s', expected %s", p.Type, blockTypeCertificate)
		}

		if p == nil {
			break
		}

		pemBlocks = r
		decodedCerts = append(decodedCerts, p.Bytes...)
	}

	return x509.ParseCertificates(decodedCerts)
}

func getRSAPrivateKeyFromString(key string) (interface{}, error) {
	// if the input is PEM handle that
	if strings.HasPrefix(key, "-----BEGIN") {
		return getRSAPrivateKeyFromPEM([]byte(key))
	}

	// assume input is base64 if not PEM
	b64, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	return getRSAPrivateKeyFromPEM(b64)
}

func getRSAPrivateKeyFromPEM(pemBlocks []byte) (interface{}, error) {

	// decode the pem into the Block struct
	p, _ := pem.Decode(pemBlocks)
	if p == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	// if the key is in PKCS1 format
	if p.Type == blockTypeRSAPrivateKey {
		return x509.ParsePKCS1PrivateKey(p.Bytes)
	}

	// if the key is in PKCS8 format
	if p.Type == blockTypePrivateKey {
		return x509.ParsePKCS8PrivateKey(p.Bytes)
	}

	// unsupported key format
	return nil, fmt.Errorf("PEM block type is '%s', expected %s or %s", p.Type, blockTypeRSAPrivateKey,
		blockTypePrivateKey)

}

// addCACertsFromFile adds CA certificates from filePath into the given pool.
// If pool is nil, it creates a new x509.CertPool. pool is returned.
func addCACertsFromFile(pool *x509.CertPool, filePath string) (*x509.CertPool, error) {
	if pool == nil {
		pool = x509.NewCertPool()
	}

	caCert, err := readCertFromFile(filePath)
	if err != nil {
		return nil, err
	}

	if ok := pool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("could not append CA certificates from %q", filePath)
	}

	return pool, nil
}

// addCACertsFromBytes adds CA certificates from pemBytes into the given pool.
// If pool is nil, it creates a new x509.CertPool. pool is returned.
func addCACertsFromBytes(pool *x509.CertPool, pemBytes []byte) (*x509.CertPool, error) {
	if pool == nil {
		pool = x509.NewCertPool()
	}

	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, fmt.Errorf("could not append certificates")
	}

	return pool, nil
}

// addCACertsFromBytes adds CA certificates from the environment variable named
// by envName into the given pool. If pool is nil, it creates a new x509.CertPool.
// pool is returned.
func addCACertsFromEnv(pool *x509.CertPool, envName string) (*x509.CertPool, error) {
	pool, err := addCACertsFromBytes(pool, []byte(os.Getenv(envName)))
	if err != nil {
		return nil, fmt.Errorf("could not add CA certificates from envvar %q: %w", envName, err)
	}

	return pool, err
}

// ReadCertFromFile reads a cert from file
func readCertFromFile(localCertFile string) ([]byte, error) {
	// Read in the cert file
	certPEM, err := ioutil.ReadFile(localCertFile)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// ReadKeyFromFile reads a key from file
func readKeyFromFile(localKeyFile string) ([]byte, error) {
	// Read in the cert file
	key, err := ioutil.ReadFile(localKeyFile)
	if err != nil {
		return nil, err
	}
	return key, nil
}
