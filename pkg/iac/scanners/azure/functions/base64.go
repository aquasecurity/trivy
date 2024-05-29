package functions

import (
	"encoding/base64"
	"encoding/json"
)

func Base64(args ...any) any {

	if len(args) == 0 {
		return nil
	}

	input := args[0].(string)

	return base64.StdEncoding.EncodeToString([]byte(input))
}

func Base64ToString(args ...any) any {
	if len(args) == 0 {
		return nil
	}

	input := args[0].(string)

	result, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return ""
	}
	return string(result)
}

func Base64ToJson(args ...any) any {

	if len(args) == 0 {
		return nil
	}

	input := args[0].(string)

	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil
	}

	var result map[string]any

	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil
	}
	return result
}
