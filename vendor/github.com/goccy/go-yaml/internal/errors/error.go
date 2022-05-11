package errors

import (
	"bytes"
	"fmt"

	"github.com/goccy/go-yaml/printer"
	"github.com/goccy/go-yaml/token"
	"golang.org/x/xerrors"
)

const (
	defaultColorize      = false
	defaultIncludeSource = true
)

var (
	ErrDecodeRequiredPointerType = xerrors.New("required pointer type value")
)

// Wrapf wrap error for stack trace
func Wrapf(err error, msg string, args ...interface{}) error {
	return &wrapError{
		baseError: &baseError{},
		err:       xerrors.Errorf(msg, args...),
		nextErr:   err,
		frame:     xerrors.Caller(1),
	}
}

// ErrSyntax create syntax error instance with message and token
func ErrSyntax(msg string, tk *token.Token) *syntaxError {
	return &syntaxError{
		baseError: &baseError{},
		msg:       msg,
		token:     tk,
		frame:     xerrors.Caller(1),
	}
}

type baseError struct {
	state fmt.State
	verb  rune
}

func (e *baseError) Error() string {
	return ""
}

func (e *baseError) chainStateAndVerb(err error) {
	wrapErr, ok := err.(*wrapError)
	if ok {
		wrapErr.state = e.state
		wrapErr.verb = e.verb
	}
	syntaxErr, ok := err.(*syntaxError)
	if ok {
		syntaxErr.state = e.state
		syntaxErr.verb = e.verb
	}
}

type wrapError struct {
	*baseError
	err     error
	nextErr error
	frame   xerrors.Frame
}

type myprinter struct {
	xerrors.Printer
	colored    bool
	inclSource bool
}

func (e *wrapError) As(target interface{}) bool {
	err := e.nextErr
	for {
		if wrapErr, ok := err.(*wrapError); ok {
			err = wrapErr.nextErr
			continue
		}
		break
	}
	return xerrors.As(err, target)
}

func (e *wrapError) Unwrap() error {
	return e.nextErr
}

func (e *wrapError) PrettyPrint(p xerrors.Printer, colored, inclSource bool) error {
	return e.FormatError(&myprinter{Printer: p, colored: colored, inclSource: inclSource})
}

func (e *wrapError) FormatError(p xerrors.Printer) error {
	if _, ok := p.(*myprinter); !ok {
		p = &myprinter{
			Printer:    p,
			colored:    defaultColorize,
			inclSource: defaultIncludeSource,
		}
	}
	if e.verb == 'v' && e.state.Flag('+') {
		// print stack trace for debugging
		p.Print(e.err, "\n")
		e.frame.Format(p)
		e.chainStateAndVerb(e.nextErr)
		return e.nextErr
	}
	err := e.nextErr
	for {
		if wrapErr, ok := err.(*wrapError); ok {
			err = wrapErr.nextErr
			continue
		}
		break
	}
	e.chainStateAndVerb(err)
	if fmtErr, ok := err.(xerrors.Formatter); ok {
		fmtErr.FormatError(p)
	} else {
		p.Print(err)
	}
	return nil
}

type wrapState struct {
	org fmt.State
}

func (s *wrapState) Write(b []byte) (n int, err error) {
	return s.org.Write(b)
}

func (s *wrapState) Width() (wid int, ok bool) {
	return s.org.Width()
}

func (s *wrapState) Precision() (prec int, ok bool) {
	return s.org.Precision()
}

func (s *wrapState) Flag(c int) bool {
	// set true to 'printDetail' forced because when p.Detail() is false, xerrors.Printer no output any text
	if c == '#' {
		// ignore '#' keyword because xerrors.FormatError doesn't set true to printDetail.
		// ( see https://github.com/golang/xerrors/blob/master/adaptor.go#L39-L43 )
		return false
	}
	return true
}

func (e *wrapError) Format(state fmt.State, verb rune) {
	e.state = state
	e.verb = verb
	xerrors.FormatError(e, &wrapState{org: state}, verb)
}

func (e *wrapError) Error() string {
	var buf bytes.Buffer
	e.PrettyPrint(&Sink{&buf}, defaultColorize, defaultIncludeSource)
	return buf.String()
}

type syntaxError struct {
	*baseError
	msg   string
	token *token.Token
	frame xerrors.Frame
}

func (e *syntaxError) PrettyPrint(p xerrors.Printer, colored, inclSource bool) error {
	return e.FormatError(&myprinter{Printer: p, colored: colored, inclSource: inclSource})
}

func (e *syntaxError) FormatError(p xerrors.Printer) error {
	var pp printer.Printer

	var colored, inclSource bool
	if mp, ok := p.(*myprinter); ok {
		colored = mp.colored
		inclSource = mp.inclSource
	}

	pos := fmt.Sprintf("[%d:%d] ", e.token.Position.Line, e.token.Position.Column)
	msg := pp.PrintErrorMessage(fmt.Sprintf("%s%s", pos, e.msg), colored)
	if inclSource {
		msg += "\n" + pp.PrintErrorToken(e.token, colored)
	}
	p.Print(msg)

	if e.verb == 'v' && e.state.Flag('+') {
		// %+v
		// print stack trace for debugging
		e.frame.Format(p)
	}
	return nil
}

type PrettyPrinter interface {
	PrettyPrint(xerrors.Printer, bool, bool) error
}
type Sink struct{ *bytes.Buffer }

func (es *Sink) Print(args ...interface{}) {
	fmt.Fprint(es.Buffer, args...)
}

func (es *Sink) Printf(f string, args ...interface{}) {
	fmt.Fprintf(es.Buffer, f, args...)
}

func (es *Sink) Detail() bool {
	return false
}

func (e *syntaxError) Error() string {
	var buf bytes.Buffer
	e.PrettyPrint(&Sink{&buf}, defaultColorize, defaultIncludeSource)
	return buf.String()
}
