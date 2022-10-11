package flag

type ConvertOptions struct {
	Source string
}

type ConvertFlagGroup struct {
}

func (f *ConvertFlagGroup) Name() string {
	return "Convert"
}

func (f *ConvertFlagGroup) Flags() []*Flag {
	return []*Flag{}
}

func (f *ConvertFlagGroup) ToOptions(args []string) (ConvertOptions, error) {
	var source string
	if len(args) == 1 {
		source = args[0]
	}
	return ConvertOptions{
		Source: source,
	}, nil
}

func NewConvertFlagGroup() *ConvertFlagGroup {
	return &ConvertFlagGroup{}
}
