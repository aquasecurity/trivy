// Copyright 2015 xeipuuv ( https://github.com/xeipuuv )
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// author           xeipuuv
// author-github    https://github.com/xeipuuv
// author-mail      xeipuuv@gmail.com
//
// repository-name  gojsonschema
// repository-desc  An implementation of JSON Schema, based on IETF's draft v4 - Go language.
//
// description		Different strategies to load JSON files.
// 					Includes References (file and HTTP), JSON strings and Go types.
//
// created          01-02-2015

package gojsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xeipuuv/gojsonreference"
)

// NOTE(sr): We need to control from which hosts remote references are
// allowed to be resolved via HTTP requests. It's quite cumbersome to
// add extra parameters to all calls and interfaces involved, so we're
// using a global variable instead:
var allowNet map[string]struct{}

func SetAllowNet(hosts []string) {
	if hosts == nil {
		allowNet = nil // resetting the global
		return
	}
	allowNet = make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		allowNet[host] = struct{}{}
	}
}

func isAllowed(ref *url.URL) bool {
	if allowNet == nil {
		return true
	}
	_, ok := allowNet[ref.Hostname()]
	return ok
}

var osFS = osFileSystem(os.Open)

// JSONLoader defines the JSON loader interface
type JSONLoader interface {
	JSONSource() interface{}
	LoadJSON() (interface{}, error)
	JSONReference() (gojsonreference.JsonReference, error)
	LoaderFactory() JSONLoaderFactory
}

// JSONLoaderFactory defines the JSON loader factory interface
type JSONLoaderFactory interface {
	// New creates a new JSON loader for the given source
	New(source string) JSONLoader
}

// DefaultJSONLoaderFactory is the default JSON loader factory
type DefaultJSONLoaderFactory struct {
}

// FileSystemJSONLoaderFactory is a JSON loader factory that uses http.FileSystem
type FileSystemJSONLoaderFactory struct {
	fs http.FileSystem
}

// New creates a new JSON loader for the given source
func (d DefaultJSONLoaderFactory) New(source string) JSONLoader {
	return &jsonReferenceLoader{
		fs:     osFS,
		source: source,
	}
}

// New creates a new JSON loader for the given source
func (f FileSystemJSONLoaderFactory) New(source string) JSONLoader {
	return &jsonReferenceLoader{
		fs:     f.fs,
		source: source,
	}
}

// osFileSystem is a functional wrapper for os.Open that implements http.FileSystem.
type osFileSystem func(string) (*os.File, error)

// Opens a file with the given name
func (o osFileSystem) Open(name string) (http.File, error) {
	return o(name)
}

// JSON Reference loader
// references are used to load JSONs from files and HTTP

type jsonReferenceLoader struct {
	fs     http.FileSystem
	source string
}

func (l *jsonReferenceLoader) JSONSource() interface{} {
	return l.source
}

func (l *jsonReferenceLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference(l.JSONSource().(string))
}

func (l *jsonReferenceLoader) LoaderFactory() JSONLoaderFactory {
	return &FileSystemJSONLoaderFactory{
		fs: l.fs,
	}
}

// NewReferenceLoader returns a JSON reference loader using the given source and the local OS file system.
func NewReferenceLoader(source string) JSONLoader {
	return &jsonReferenceLoader{
		fs:     osFS,
		source: source,
	}
}

// NewReferenceLoaderFileSystem returns a JSON reference loader using the given source and file system.
func NewReferenceLoaderFileSystem(source string, fs http.FileSystem) JSONLoader {
	return &jsonReferenceLoader{
		fs:     fs,
		source: source,
	}
}

func (l *jsonReferenceLoader) LoadJSON() (interface{}, error) {

	var err error

	reference, err := gojsonreference.NewJsonReference(l.JSONSource().(string))
	if err != nil {
		return nil, err
	}

	refToURL := reference
	refToURL.GetUrl().Fragment = ""

	if reference.HasFileScheme {

		filename := strings.TrimPrefix(refToURL.String(), "file://")
		filename, err = url.QueryUnescape(filename)

		if err != nil {
			return nil, err
		}

		if runtime.GOOS == "windows" {
			// on Windows, a file URL may have an extra leading slash, use slashes
			// instead of backslashes, and have spaces escaped
			filename = strings.TrimPrefix(filename, "/")
			filename = filepath.FromSlash(filename)
		}

		return l.loadFromFile(filename)
	}

	// NOTE(sr): hardcoded metaschema references are not subject to allow_net
	// checking; their contents are hardcoded in the library!
	//
	// returned cached versions for metaschemas for drafts 4, 6 and 7
	// for performance and allow for easier offline use
	if metaSchema := drafts.GetMetaSchema(refToURL.String()); metaSchema != "" {
		return decodeJSONUsingNumber(strings.NewReader(metaSchema))
	}

	if isAllowed(refToURL.GetUrl()) {
		return l.loadFromHTTP(refToURL.String())
	}

	return nil, fmt.Errorf("remote reference loading disabled: %s", reference.String())
}

func (l *jsonReferenceLoader) loadFromHTTP(address string) (interface{}, error) {

	resp, err := http.Get(address)
	if err != nil {
		return nil, err
	}

	// must return HTTP Status 200 OK
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(formatErrorDescription(Locale.HTTPBadStatus(), ErrorDetails{"status": resp.Status}))
	}

	bodyBuff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return decodeJSONUsingNumber(bytes.NewReader(bodyBuff))
}

func (l *jsonReferenceLoader) loadFromFile(path string) (interface{}, error) {
	f, err := l.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bodyBuff, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return decodeJSONUsingNumber(bytes.NewReader(bodyBuff))

}

// JSON string loader

type jsonStringLoader struct {
	source string
}

func (l *jsonStringLoader) JSONSource() interface{} {
	return l.source
}

func (l *jsonStringLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference("#")
}

func (l *jsonStringLoader) LoaderFactory() JSONLoaderFactory {
	return &DefaultJSONLoaderFactory{}
}

// NewStringLoader creates a new JSONLoader, taking a string as source
func NewStringLoader(source string) JSONLoader {
	return &jsonStringLoader{source: source}
}

func (l *jsonStringLoader) LoadJSON() (interface{}, error) {

	return decodeJSONUsingNumber(strings.NewReader(l.JSONSource().(string)))

}

// JSON bytes loader

type jsonBytesLoader struct {
	source []byte
}

func (l *jsonBytesLoader) JSONSource() interface{} {
	return l.source
}

func (l *jsonBytesLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference("#")
}

func (l *jsonBytesLoader) LoaderFactory() JSONLoaderFactory {
	return &DefaultJSONLoaderFactory{}
}

// NewBytesLoader creates a new JSONLoader, taking a `[]byte` as source
func NewBytesLoader(source []byte) JSONLoader {
	return &jsonBytesLoader{source: source}
}

func (l *jsonBytesLoader) LoadJSON() (interface{}, error) {
	return decodeJSONUsingNumber(bytes.NewReader(l.JSONSource().([]byte)))
}

// JSON Go (types) loader
// used to load JSONs from the code as maps, interface{}, structs ...

type jsonGoLoader struct {
	source interface{}
}

func (l *jsonGoLoader) JSONSource() interface{} {
	return l.source
}

func (l *jsonGoLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference("#")
}

func (l *jsonGoLoader) LoaderFactory() JSONLoaderFactory {
	return &DefaultJSONLoaderFactory{}
}

// NewGoLoader creates a new JSONLoader from a given Go struct
func NewGoLoader(source interface{}) JSONLoader {
	return &jsonGoLoader{source: source}
}

func (l *jsonGoLoader) LoadJSON() (interface{}, error) {

	// convert it to a compliant JSON first to avoid types "mismatches"

	jsonBytes, err := json.Marshal(l.JSONSource())
	if err != nil {
		return nil, err
	}

	return decodeJSONUsingNumber(bytes.NewReader(jsonBytes))

}

type jsonIOLoader struct {
	buf *bytes.Buffer
}

// NewReaderLoader creates a new JSON loader using the provided io.Reader
func NewReaderLoader(source io.Reader) (JSONLoader, io.Reader) {
	buf := &bytes.Buffer{}
	return &jsonIOLoader{buf: buf}, io.TeeReader(source, buf)
}

// NewWriterLoader creates a new JSON loader using the provided io.Writer
func NewWriterLoader(source io.Writer) (JSONLoader, io.Writer) {
	buf := &bytes.Buffer{}
	return &jsonIOLoader{buf: buf}, io.MultiWriter(source, buf)
}

func (l *jsonIOLoader) JSONSource() interface{} {
	return l.buf.String()
}

func (l *jsonIOLoader) LoadJSON() (interface{}, error) {
	return decodeJSONUsingNumber(l.buf)
}

func (l *jsonIOLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference("#")
}

func (l *jsonIOLoader) LoaderFactory() JSONLoaderFactory {
	return &DefaultJSONLoaderFactory{}
}

// JSON raw loader
// In case the JSON is already marshalled to interface{} use this loader
// This is used for testing as otherwise there is no guarantee the JSON is marshalled
// "properly" by using https://golang.org/pkg/encoding/json/#Decoder.UseNumber
type jsonRawLoader struct {
	source interface{}
}

// NewRawLoader creates a new JSON raw loader for the given source
func NewRawLoader(source interface{}) JSONLoader {
	return &jsonRawLoader{source: source}
}
func (l *jsonRawLoader) JSONSource() interface{} {
	return l.source
}
func (l *jsonRawLoader) LoadJSON() (interface{}, error) {
	return l.source, nil
}
func (l *jsonRawLoader) JSONReference() (gojsonreference.JsonReference, error) {
	return gojsonreference.NewJsonReference("#")
}
func (l *jsonRawLoader) LoaderFactory() JSONLoaderFactory {
	return &DefaultJSONLoaderFactory{}
}

func decodeJSONUsingNumber(r io.Reader) (interface{}, error) {

	var document interface{}

	decoder := json.NewDecoder(r)
	decoder.UseNumber()

	err := decoder.Decode(&document)
	if err != nil {
		return nil, err
	}

	return document, nil

}
