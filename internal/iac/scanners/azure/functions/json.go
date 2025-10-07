package functions

import "encoding/json"

func JSON(args ...any) any {
	if len(args) != 1 {
		return ""
	}

	value, ok := args[0].(string)
	if !ok {
		return ""
	}

	var jsonType map[string]any
	if err := json.Unmarshal([]byte(value), &jsonType); err != nil {
		return ""
	}
	return jsonType
}
