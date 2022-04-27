package sarif

import "encoding/json"

func getJsonString(value interface{}) string {
	j, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(j)
}
