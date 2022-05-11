package sarif

// Exception ...
type Exception struct {
	InnerExceptions []*Exception `json:"innerExceptions,omitempty"`
	Kind            *string      `json:"kind,omitempty"`
	Message         *string      `json:"message,omitempty"`
	Stack           *Stack       `json:"stack,omitempty"`
	PropertyBag

}

// NewException creates a new Exception and returns a pointer to it
func NewException() *Exception {
	return &Exception{}
}

// WithMessage sets the Message
func (exception *Exception) WithMessage(message string) *Exception {
	exception.Message = &message
	return exception
}

// WithKind sets the Kind
func (exception *Exception) WithKind(kind string) *Exception {
	exception.Kind = &kind
	return exception
}

// WithStack sets the Stack
func (exception *Exception) WithStack(stack Stack) *Exception {
	exception.Stack = &stack
	return exception
}

// WithInnerExceptions sets the InnerExceptions
func (exception *Exception) WithInnerExceptions(exceptions []*Exception) *Exception {
	exception.InnerExceptions = exceptions
	return exception
}

// AddInnerException ...
func (exception *Exception) AddInnerException(toAdd *Exception) {
	exception.InnerExceptions = append(exception.InnerExceptions, toAdd)
}
