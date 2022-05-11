package env

import (
	"encoding"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// nolint: gochecknoglobals
var (
	// ErrNotAStructPtr is returned if you pass something that is not a pointer to a
	// Struct to Parse.
	ErrNotAStructPtr = errors.New("env: expected a pointer to a Struct")

	defaultBuiltInParsers = map[reflect.Kind]ParserFunc{
		reflect.Bool: func(v string) (interface{}, error) {
			return strconv.ParseBool(v)
		},
		reflect.String: func(v string) (interface{}, error) {
			return v, nil
		},
		reflect.Int: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 32)
			return int(i), err
		},
		reflect.Int16: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 16)
			return int16(i), err
		},
		reflect.Int32: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 32)
			return int32(i), err
		},
		reflect.Int64: func(v string) (interface{}, error) {
			return strconv.ParseInt(v, 10, 64)
		},
		reflect.Int8: func(v string) (interface{}, error) {
			i, err := strconv.ParseInt(v, 10, 8)
			return int8(i), err
		},
		reflect.Uint: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 32)
			return uint(i), err
		},
		reflect.Uint16: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 16)
			return uint16(i), err
		},
		reflect.Uint32: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 32)
			return uint32(i), err
		},
		reflect.Uint64: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 64)
			return i, err
		},
		reflect.Uint8: func(v string) (interface{}, error) {
			i, err := strconv.ParseUint(v, 10, 8)
			return uint8(i), err
		},
		reflect.Float64: func(v string) (interface{}, error) {
			return strconv.ParseFloat(v, 64)
		},
		reflect.Float32: func(v string) (interface{}, error) {
			f, err := strconv.ParseFloat(v, 32)
			return float32(f), err
		},
	}

	defaultTypeParsers = map[reflect.Type]ParserFunc{
		reflect.TypeOf(url.URL{}): func(v string) (interface{}, error) {
			u, err := url.Parse(v)
			if err != nil {
				return nil, fmt.Errorf("unable to parse URL: %v", err)
			}
			return *u, nil
		},
		reflect.TypeOf(time.Nanosecond): func(v string) (interface{}, error) {
			s, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("unable to parse duration: %v", err)
			}
			return s, err
		},
	}
)

// ParserFunc defines the signature of a function that can be used within `CustomParsers`.
type ParserFunc func(v string) (interface{}, error)

// OnSetFn is a hook that can be run when a value is set.
type OnSetFn func(tag string, value interface{}, isDefault bool)

// Options for the parser.
type Options struct {
	// Environment keys and values that will be accessible for the service.
	Environment map[string]string

	// TagName specifies another tagname to use rather than the default env.
	TagName string

	// RequiredIfNoDef automatically sets all env as required if they do not declare 'envDefault'
	RequiredIfNoDef bool

	// OnSet allows to run a function when a value is set
	OnSet OnSetFn

	// Prefix define a prefix for each key
	Prefix string

	// Sets to true if we have already configured once.
	configured bool
}

// configure will do the basic configurations and defaults.
func configure(opts []Options) []Options {
	// If we have already configured the first item
	// of options will have been configured set to true.
	if len(opts) > 0 && opts[0].configured {
		return opts
	}

	// Created options with defaults.
	opt := Options{
		TagName:     "env",
		Environment: toMap(os.Environ()),
		configured:  true,
	}

	// Loop over all opts structs and set
	// to opt if value is not default/empty.
	for _, item := range opts {
		if item.Environment != nil {
			opt.Environment = item.Environment
		}
		if item.TagName != "" {
			opt.TagName = item.TagName
		}
		if item.OnSet != nil {
			opt.OnSet = item.OnSet
		}
		if item.Prefix != "" {
			opt.Prefix = item.Prefix
		}
		opt.RequiredIfNoDef = item.RequiredIfNoDef
	}

	return []Options{opt}
}

func getOnSetFn(opts []Options) OnSetFn {
	return opts[0].OnSet
}

// getTagName returns the tag name.
func getTagName(opts []Options) string {
	return opts[0].TagName
}

// getEnvironment returns the environment map.
func getEnvironment(opts []Options) map[string]string {
	return opts[0].Environment
}

// Parse parses a struct containing `env` tags and loads its values from
// environment variables.
func Parse(v interface{}, opts ...Options) error {
	return ParseWithFuncs(v, map[reflect.Type]ParserFunc{}, opts...)
}

// ParseWithFuncs is the same as `Parse` except it also allows the user to pass
// in custom parsers.
func ParseWithFuncs(v interface{}, funcMap map[reflect.Type]ParserFunc, opts ...Options) error {
	opts = configure(opts)

	ptrRef := reflect.ValueOf(v)
	if ptrRef.Kind() != reflect.Ptr {
		return ErrNotAStructPtr
	}
	ref := ptrRef.Elem()
	if ref.Kind() != reflect.Struct {
		return ErrNotAStructPtr
	}
	parsers := defaultTypeParsers
	for k, v := range funcMap {
		parsers[k] = v
	}

	return doParse(ref, parsers, opts)
}

func doParse(ref reflect.Value, funcMap map[reflect.Type]ParserFunc, opts []Options) error {
	refType := ref.Type()

	for i := 0; i < refType.NumField(); i++ {
		refField := ref.Field(i)
		if !refField.CanSet() {
			continue
		}
		if reflect.Ptr == refField.Kind() && !refField.IsNil() {
			if refField.Elem().Kind() == reflect.Struct {
				if err := ParseWithFuncs(refField.Interface(), funcMap, optsWithPrefix(refType.Field(i), opts)...); err != nil {
					return err
				}
				continue
			}
			if err := ParseWithFuncs(refField.Interface(), funcMap, opts...); err != nil {
				return err
			}
			continue
		}
		if reflect.Struct == refField.Kind() && refField.CanAddr() && refField.Type().Name() == "" {
			if err := Parse(refField.Addr().Interface(), optsWithPrefix(refType.Field(i), opts)...); err != nil {
				return err
			}
			continue
		}
		refTypeField := refType.Field(i)
		value, err := get(refTypeField, opts)
		if err != nil {
			return err
		}
		if value == "" {
			if reflect.Struct == refField.Kind() {
				if err := doParse(refField, funcMap, optsWithPrefix(refType.Field(i), opts)); err != nil {
					return err
				}
			}
			continue
		}
		if err := set(refField, refTypeField, value, funcMap); err != nil {
			return err
		}
	}
	return nil
}

func get(field reflect.StructField, opts []Options) (val string, err error) {
	var exists bool
	var isDefault bool
	var loadFile bool
	var unset bool
	var notEmpty bool

	required := opts[0].RequiredIfNoDef
	prefix := opts[0].Prefix
	key, tags := parseKeyForOption(field.Tag.Get(getTagName(opts)))
	key = prefix + key
	for _, tag := range tags {
		switch tag {
		case "":
			continue
		case "file":
			loadFile = true
		case "required":
			required = true
		case "unset":
			unset = true
		case "notEmpty":
			notEmpty = true
		default:
			return "", fmt.Errorf("env: tag option %q not supported", tag)
		}
	}
	expand := strings.EqualFold(field.Tag.Get("envExpand"), "true")
	defaultValue, defExists := field.Tag.Lookup("envDefault")
	val, exists, isDefault = getOr(key, defaultValue, defExists, getEnvironment(opts))

	if expand {
		val = os.ExpandEnv(val)
	}

	if unset {
		defer os.Unsetenv(key)
	}

	if required && !exists && len(key) > 0 {
		return "", fmt.Errorf(`env: required environment variable %q is not set`, key)
	}

	if notEmpty && val == "" {
		return "", fmt.Errorf("env: environment variable %q should not be empty", key)
	}

	if loadFile && val != "" {
		filename := val
		val, err = getFromFile(filename)
		if err != nil {
			return "", fmt.Errorf(`env: could not load content of file "%s" from variable %s: %v`, filename, key, err)
		}
	}

	if onSetFn := getOnSetFn(opts); onSetFn != nil {
		onSetFn(key, val, isDefault)
	}
	return val, err
}

// split the env tag's key into the expected key and desired option, if any.
func parseKeyForOption(key string) (string, []string) {
	opts := strings.Split(key, ",")
	return opts[0], opts[1:]
}

func getFromFile(filename string) (value string, err error) {
	b, err := os.ReadFile(filename)
	return string(b), err
}

func getOr(key, defaultValue string, defExists bool, envs map[string]string) (string, bool, bool) {
	value, exists := envs[key]
	switch {
	case (!exists || key == "") && defExists:
		return defaultValue, true, true
	case !exists:
		return "", false, false
	}

	return value, true, false
}

func set(field reflect.Value, sf reflect.StructField, value string, funcMap map[reflect.Type]ParserFunc) error {
	if tm := asTextUnmarshaler(field); tm != nil {
		if err := tm.UnmarshalText([]byte(value)); err != nil {
			return newParseError(sf, err)
		}
		return nil
	}

	typee := sf.Type
	fieldee := field
	if typee.Kind() == reflect.Ptr {
		typee = typee.Elem()
		fieldee = field.Elem()
	}

	parserFunc, ok := funcMap[typee]
	if ok {
		val, err := parserFunc(value)
		if err != nil {
			return newParseError(sf, err)
		}

		fieldee.Set(reflect.ValueOf(val))
		return nil
	}

	parserFunc, ok = defaultBuiltInParsers[typee.Kind()]
	if ok {
		val, err := parserFunc(value)
		if err != nil {
			return newParseError(sf, err)
		}

		fieldee.Set(reflect.ValueOf(val).Convert(typee))
		return nil
	}

	if field.Kind() == reflect.Slice {
		return handleSlice(field, value, sf, funcMap)
	}

	return newNoParserError(sf)
}

func handleSlice(field reflect.Value, value string, sf reflect.StructField, funcMap map[reflect.Type]ParserFunc) error {
	separator := sf.Tag.Get("envSeparator")
	if separator == "" {
		separator = ","
	}
	parts := strings.Split(value, separator)

	typee := sf.Type.Elem()
	if typee.Kind() == reflect.Ptr {
		typee = typee.Elem()
	}

	if _, ok := reflect.New(typee).Interface().(encoding.TextUnmarshaler); ok {
		return parseTextUnmarshalers(field, parts, sf)
	}

	parserFunc, ok := funcMap[typee]
	if !ok {
		parserFunc, ok = defaultBuiltInParsers[typee.Kind()]
		if !ok {
			return newNoParserError(sf)
		}
	}

	result := reflect.MakeSlice(sf.Type, 0, len(parts))
	for _, part := range parts {
		r, err := parserFunc(part)
		if err != nil {
			return newParseError(sf, err)
		}
		v := reflect.ValueOf(r).Convert(typee)
		if sf.Type.Elem().Kind() == reflect.Ptr {
			v = reflect.New(typee)
			v.Elem().Set(reflect.ValueOf(r).Convert(typee))
		}
		result = reflect.Append(result, v)
	}
	field.Set(result)
	return nil
}

func asTextUnmarshaler(field reflect.Value) encoding.TextUnmarshaler {
	if reflect.Ptr == field.Kind() {
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
	} else if field.CanAddr() {
		field = field.Addr()
	}

	tm, ok := field.Interface().(encoding.TextUnmarshaler)
	if !ok {
		return nil
	}
	return tm
}

func parseTextUnmarshalers(field reflect.Value, data []string, sf reflect.StructField) error {
	s := len(data)
	elemType := field.Type().Elem()
	slice := reflect.MakeSlice(reflect.SliceOf(elemType), s, s)
	for i, v := range data {
		sv := slice.Index(i)
		kind := sv.Kind()
		if kind == reflect.Ptr {
			sv = reflect.New(elemType.Elem())
		} else {
			sv = sv.Addr()
		}
		tm := sv.Interface().(encoding.TextUnmarshaler)
		if err := tm.UnmarshalText([]byte(v)); err != nil {
			return newParseError(sf, err)
		}
		if kind == reflect.Ptr {
			slice.Index(i).Set(sv)
		}
	}

	field.Set(slice)

	return nil
}

func newParseError(sf reflect.StructField, err error) error {
	if err == nil {
		return nil
	}
	return parseError{
		sf:  sf,
		err: err,
	}
}

type parseError struct {
	sf  reflect.StructField
	err error
}

func (e parseError) Error() string {
	return fmt.Sprintf(`env: parse error on field "%s" of type "%s": %v`, e.sf.Name, e.sf.Type, e.err)
}

func newNoParserError(sf reflect.StructField) error {
	return fmt.Errorf(`env: no parser found for field "%s" of type "%s"`, sf.Name, sf.Type)
}

func optsWithPrefix(field reflect.StructField, opts []Options) []Options {
	subOpts := make([]Options, len(opts))
	copy(subOpts, opts)
	if prefix := field.Tag.Get("envPrefix"); prefix != "" {
		subOpts[0].Prefix += prefix
	}
	return subOpts
}
