package functions

import "encoding/json"

func JSON(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	value, ok := args[0].(string)
	if !ok {
		return ""
	}

	var jsonType map[string]interface{}
	if err := json.Unmarshal([]byte(value), &jsonType); err != nil {
		return ""
	}
	return jsonType
}
