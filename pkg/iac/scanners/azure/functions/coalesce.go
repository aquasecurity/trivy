package functions

func Coalesce(args ...any) any {
	for _, arg := range args {
		if arg != nil {
			return arg
		}
	}
	return nil
}
