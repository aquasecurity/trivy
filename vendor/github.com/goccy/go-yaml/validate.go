package yaml

// StructValidator need to implement Struct method only
// ( see https://godoc.org/gopkg.in/go-playground/validator.v9#Validate.Struct )
type StructValidator interface {
	Struct(interface{}) error
}

// FieldError need to implement StructField method only
// ( see https://godoc.org/gopkg.in/go-playground/validator.v9#FieldError )
type FieldError interface {
	StructField() string
}
