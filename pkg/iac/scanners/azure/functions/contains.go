package functions

import (
	"fmt"
	"strings"
)

func Contains(args ...interface{}) interface{} {

	if len(args) != 2 {
		return false
	}

	container := args[0]
	itemToFind := args[1]

	switch cType := container.(type) {
	case string:
		switch iType := itemToFind.(type) {
		case string:
			return strings.Contains(strings.ToLower(cType), strings.ToLower(iType))
		case int, int32, int64, uint, uint32, uint64:
			return strings.Contains(strings.ToLower(cType), fmt.Sprintf("%d", iType))
		}
	case []interface{}:
		for _, item := range cType {
			if item == itemToFind {
				return true
			}
		}
	case map[string]interface{}:
		for key := range cType {
			if key == itemToFind {
				return true
			}
		}
	}

	return false
}
