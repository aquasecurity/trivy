package functions

func Coalesce(args ...interface{}) interface{} {
	for _, arg := range args {
		if arg != nil {
			return arg
		}
	}
	return nil
}
