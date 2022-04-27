package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// Version is the version of Sarif to use
type Version string

// Version210 represents Version210 of Sarif
const Version210 Version = "2.1.0"

var versions = map[Version]string{
	Version210: "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
}

// Report is the encapsulating type representing a Sarif Report
type Report struct {
	PropertyBag
	InlineExternalProperties []*ExternalProperties `json:"inlineExternalProperties,omitempty"`
	Version                  string                `json:"version"`
	Schema                   string                `json:"$schema,omitempty"`
	Runs                     []*Run                `json:"runs"`
}

// New Creates a new Report or returns an error
func New(version Version, includeSchema... bool) (*Report, error) {
  schema := ""

  if len(includeSchema) == 0 || includeSchema[0] {
    var err error

	  schema, err = getVersionSchema(version)
	  if err != nil {
		  return nil, err
	  }
  }
	return &Report{
		Version: string(version),
		Schema:  schema,
		Runs:    []*Run{},
	}, nil
}

// Open loads a Report from a file
func Open(filename string) (*Report, error) {
	if _, err := os.Stat(filename); err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("the provided file path doesn't have a file")
	}

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("the provided filepath could not be opened. %w", err)
	}
	return FromBytes(content)
}

// FromString loads a Report from string content
func FromString(content string) (*Report, error) {
	return FromBytes([]byte(content))
}

// FromBytes loads a Report from a byte array
func FromBytes(content []byte) (*Report, error) {
	var report Report
	if err := json.Unmarshal(content, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// AddRun allows adding run information to the current report
func (sarif *Report) AddRun(run *Run) {
	sarif.Runs = append(sarif.Runs, run)
}

func getVersionSchema(version Version) (string, error) {
	for ver, schema := range versions {
		if ver == version {
			return schema, nil
		}
	}
	return "", fmt.Errorf("version [%s] is not supported", version)
}

// WriteFile will write the report to a file using a pretty formatter
func (sarif *Report) WriteFile(filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return sarif.PrettyWrite(file)
}

// Write writes the JSON as a string with no formatting
func (sarif *Report) Write(w io.Writer) error {
	for _, run := range sarif.Runs {
		run.DedupeArtifacts()
	}
	marshal, err := json.Marshal(sarif)
	if err != nil {
		return err
	}
	_, err = w.Write(marshal)
	return err
}

// PrettyWrite writes the JSON output with indentation
func (sarif *Report) PrettyWrite(w io.Writer) error {
	marshal, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(marshal)
	return err
}
