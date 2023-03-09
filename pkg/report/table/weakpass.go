package table

import (
	"bytes"
	"sync"

	"github.com/aquasecurity/tml"

	"github.com/aquasecurity/table"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type weakPassRenderer struct {
	w           *bytes.Buffer
	tableWriter *table.Table
	result      types.Result
	severities  []dbTypes.Severity
	isTerminal  bool
	once        *sync.Once
}

func NewWeakPassRenderer(result types.Result, isTerminal bool, severities []dbTypes.Severity) *weakPassRenderer {
	buf := bytes.NewBuffer([]byte{})
	return &weakPassRenderer{
		w:           buf,
		tableWriter: newTableWriter(buf, isTerminal),
		result:      result,
		severities:  severities,
		isTerminal:  isTerminal,
		once:        new(sync.Once),
	}
}

func (r *weakPassRenderer) Render() string {
	r.setHeaders()
	r.setRows()

	total := len(r.result.WeakPass)

	target := "weak password"
	RenderTarget(r.w, target, r.isTerminal)
	r.printf("Total: %d\n\n", total)

	r.tableWriter.Render()

	return r.w.String()
}

func (r weakPassRenderer) setHeaders() {
	header := []string{"Username", "Password", "Filepath", "ServiceType"}
	r.tableWriter.SetHeaders(header...)
}

func (r weakPassRenderer) setRows() {
	for _, l := range r.result.WeakPass {
		var row []string
		if r.isTerminal {
			row = []string{
				l.Username, l.Password, l.Filepath, l.ServiceType.String(),
			}
		} else {
			row = []string{
				l.Username, l.Password, l.Filepath, l.ServiceType.String(),
			}
		}
		r.tableWriter.AddRow(row...)
	}
}

func (r *weakPassRenderer) printf(format string, args ...interface{}) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}
