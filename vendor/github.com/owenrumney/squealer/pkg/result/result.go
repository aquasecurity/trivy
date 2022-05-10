package result

type StringScanResult struct {
	Description        string
	TransgressionFound bool
}

var CleanResult = StringScanResult{}

func NewTransgressionResult(description string) StringScanResult {
	return StringScanResult{
		TransgressionFound: true,
		Description:        description,
	}
}
